#!/usr/bin/env python2.7
#
# Copyright (c) 2014-2015 Arista Networks, Inc.  All rights reserved
# Arista Networks, Inc. Confidential and Proprietary
#
# Override pylint in a few areas due to config and command line to method
# invocation scheme used.
# pylint: disable = wildcard-import, unused-wildcard-import, broad-except, no-self-use
# pylint: disable = unused-argument

''' main entry point for DirectFlow Assist
'''

import sys
import os
import traceback
import logging
import inspect
import socket
import time
import subprocess
from .__init__ import __version__
from . import SyslogListener
from . import DirectFlowSwitch
from . import util
from directflow_assist.common import utils
import config


SHUNT_MODE_STATIC_BINDING_FLOWS = [
    ('STATIC_THRU_FIREWALL', config.SWITCH_INTERFACE_A, config.SWITCH_INTERFACE_AF,
     config.SWITCH_INTERFACE_HA_AF),
    ('STATIC_THRU_FIREWALL', config.SWITCH_INTERFACE_B, config.SWITCH_INTERFACE_BF,
     config.SWITCH_INTERFACE_HA_BF)]

INLINE_MODE_STATIC_BINDING_FLOWS = [
    ('STATIC_TO_FIREWALL', config.SWITCH_INTERFACE_A, config.SWITCH_INTERFACE_AF,
     config.SWITCH_INTERFACE_HA_AF)]

MIRROR_AND_SHUNT_MODE_RETURN_STATIC_BINDING_FLOWS = [
    ('STATIC_FROM_FIREWALL', config.SWITCH_INTERFACE_AF, config.SWITCH_INTERFACE_A),
    ('STATIC_FROM_FIREWALL', config.SWITCH_INTERFACE_BF, config.SWITCH_INTERFACE_B)]

MIRROR_AND_SHUNT_MODE_BYPASS_AND_MIRROR_FLOWS = [
    ('STATIC_BYPASS_FW', config.SWITCH_INTERFACE_A, config.SWITCH_INTERFACE_B,
     config.SWITCH_INTERFACES_TO_FW_TAP),
    ('STATIC_BYPASS_FW', config.SWITCH_INTERFACE_B, config.SWITCH_INTERFACE_A,
     config.SWITCH_INTERFACES_TO_FW_TAP)]

SETUP_COMMENT = {
    'cmd': 'comment',
    'input': ('DO NOT DELETE before confirming there are no L2 loops\nEOF')}


class Assist(object):
    ''' main entry point controller class
    '''
    def __init__(self):
        self.methods = {}
        for mem in inspect.getmembers(
                self, predicate=lambda y: inspect.ismethod(y)):
            self.methods[mem[0]] = mem[1]

    def setup_start(self, args):
        ''' exec setup then start; useful for starting from event-handler in
            running-config
        '''
        if is_valid_dfa_installation() and not is_already_running():
            self.setup(args)
            self.start(args)

    def start(self, args):
        ''' Fork a new process to run immortalize to start DFA
        '''
        if is_valid_dfa_installation() and not is_already_running():
            print 'Starting %s v%s' % (config.APP_NAME, __version__)
            subprocess.Popen('sudo immortalize --daemonize assist _run',
                             shell=True)

    def _run(self, args):
        ''' launch main DFA firewall syslog message listener
            hidden, should only be called from start()
        '''
        SyslogListener.main()

    def stop(self, args):
        ''' stop DFA listening for syslog msgs from FW
        '''
        print 'Stopping %s ...' % config.APP_NAME
        # first kill immortalizer
        cmd = "sudo pkill -f 'python /usr/bin/immortalize --daemon.* assist '"
        utils.exec_shell_cmd(cmd, echo=False)
        # DFA main thread shuts down other theads cleanly when pid file removed
        utils.exec_shell_cmd('sudo rm %s' % util.pid_filename(), echo=False)
        time.sleep(5)

    def stat(self, args):
        ''' dump status info
        '''
        print 'DirectFlow Assist Status:'
        print 'Version: %s' % __version__
        print 'Operating mode: %s' % config.OPERATING_MODE
        print 'Syslog transport: %s' % config.SYSLOG_TRANSPORT
        print 'Switch hostname: %s' % socket.gethostname()
        print 'eAPI protocol: %s' % config.SWITCH['eapi_protocol']
        # print 'eAPI target: %s' % config.SWITCH['ip']
        print 'Package path: %s' % os.path.dirname(globals()['__file__'])
        print 'Syslog Message class: %s' % config.get_msg_class()

    def status(self, args):
        ''' dump status info
        '''
        self.stat(args)
        if not is_valid_dfa_installation():
            return 1
        dfs = DirectFlowSwitch.get_directflow_switch()
        tcam = dfs.tcam_directflow_utilization()
        if tcam:
            print ('TCAM DirectFlow entries: %s, available: %s, util: %s%%'
                   % (tcam['num_used'], tcam['num_avail'], tcam['pct_used']))
        print 'Process and iptables port status:\n' + '-' * 34
        utils.exec_shell_cmd('ps -ef | egrep "python.*assist.*run" | '
                             'grep -v grep', echo=False)
        self.check_iptables()
        print

    def setup(self, args):
        ''' setup logging, validate config file, set no mac address learning
            on interfaces connected to firewall, install static flows
        '''
        try:
            utils.setup_logging(config.LOG_FILE, config.MIN_LOG_LEVEL)
        except Exception:
            traceback.print_exc()
            print ('ERROR: unable to setup logging, verify write permissions '
                   'or run as sudo')
            utils.dump_envt()
            return

        if not is_valid_dfa_installation():
            return 1
        logging.info('** running setup **')
        if (config.OPERATING_MODE == config.SHUNT_MODE or
                config.OPERATING_MODE == config.MIRROR_AND_SHUNT_MODE):
            self.cfg_interfaces_to_firewall()

        if config.OPERATING_MODE == config.SHUNT_MODE:
            self.setup_shunt_mode()
        elif config.OPERATING_MODE == config.INLINE_MODE:
            self.setup_inline_mode()
        elif (config.OPERATING_MODE == config.MIRROR_AND_SHUNT_MODE or
              config.OPERATING_MODE == config.MIRROR_MODE):
            self.setup_mirror_modes()
        else:
            print 'ERROR undefined mode: %s' % config.OPERATING_MODE
            return 1

    def cfg_interfaces_to_firewall(self):
        ''' interfaces to/from firewall create an L2 loop that STP will detect.
            STATIC flow entries prevent traffic from looping.
            Set bpdufilter enable to allow traffic to flow.
            Also set no mac address learning on interfaces connected to firewall
        '''
        logging.info('config STP bpdufilter & storm-control, disable mac addr learning'
                     ' on intf to/from firewall')
        switch_intf_to_fw = [config.SWITCH_INTERFACE_AF,
                             config.SWITCH_INTERFACE_BF,
                             config.SWITCH_INTERFACE_HA_AF,
                             config.SWITCH_INTERFACE_HA_BF]
        dfs = DirectFlowSwitch.get_directflow_switch()
        for intf in switch_intf_to_fw:
            if intf:
                cmds = ['enable', 'configure', 'interface %s' % intf,
                        'no switchport mac address learning',
                        'spanning-tree bpdufilter enable',
                        'storm-control broadcast level %s'
                        % config.STORM_CONTROL_BCAST_LEVEL,
                        'storm-control multicast level %s'
                        % config.STORM_CONTROL_MCAST_LEVEL]
                logging.info('Sending config cmds to switch: \n%s',
                             utils.format_cli_cmds_for_printing(cmds))
                dfs.exec_eapi_cmds(cmds)

    def setup_shunt_mode(self):
        ''' install static flows
        '''
        logging.info('running assist setup, setting up static flow entries')
        flowspec_list = []
        for sbf in SHUNT_MODE_STATIC_BINDING_FLOWS:
            fw_intf = sbf[2] if not sbf[3] else '%s,%s' % (sbf[2], sbf[3])
            name = utils.scrub_flow_name(
                '%s__in:%s__out:%s' % (sbf[0], sbf[1], fw_intf))
            fsp = {'name': name,
                   'match': ['input interface %s' % sbf[1]],
                   'action': ['output interface %s' % fw_intf],
                   'priority': config.PRIORITY_STATIC_PORT_BINDING_FLOW,
                   'comment': SETUP_COMMENT}
            flowspec_list.append(fsp)
            # now setup opposite direction
            name = utils.scrub_flow_name(
                '%s__in:%s__out:%s' % (sbf[0], fw_intf, sbf[1]))
            fsp = {'name': name,
                   'match': ['input interface %s' % fw_intf],
                   'action': ['output interface %s' % sbf[1]],
                   'priority': config.PRIORITY_STATIC_PORT_BINDING_FLOW,
                   'comment': SETUP_COMMENT}
            flowspec_list.append(fsp)

        print 'Creating static port binding flows via DirectFlow:'
        # print 'fspec_list: %s' % utils.unpack( flowspec_list )
        for fsp in flowspec_list:
            print '  %s' % fsp['name']
        DirectFlowSwitch.get_directflow_switch().add_flows(flowspec_list)

    def setup_inline_mode(self):
        ''' install static flows
        '''
        logging.info('running assist setup, setting up static flow entries')
        flowspec_list = []
        for sbf in INLINE_MODE_STATIC_BINDING_FLOWS:
            fw_intf = sbf[2] if not sbf[3] else '%s,%s' % (sbf[2], sbf[3])
            name = utils.scrub_flow_name(
                '%s__in:%s__out:%s' % (sbf[0], sbf[1], fw_intf))
            fsp = {'name': name,
                   'match': ['input interface %s' % sbf[1]],
                   'action': ['output interface %s' % fw_intf],
                   'priority': config.PRIORITY_STATIC_PORT_BINDING_FLOW,
                   'comment': SETUP_COMMENT}
            flowspec_list.append(fsp)
            # now setup opposite direction
            name = utils.scrub_flow_name(
                '%s__in:%s__out:%s' % (sbf[0], fw_intf, sbf[1]))
            fsp = {'name': name,
                   'match': ['input interface %s' % fw_intf],
                   'action': ['output interface %s' % sbf[1]],
                   'priority': config.PRIORITY_STATIC_PORT_BINDING_FLOW,
                   'comment': SETUP_COMMENT}
            flowspec_list.append(fsp)

        print 'Creating static port binding flows via DirectFlow:'
        # print 'fspec_list: %s' % utils.unpack( flowspec_list )
        for fsp in flowspec_list:
            print '  %s' % fsp['name']
        DirectFlowSwitch.get_directflow_switch().add_flows(flowspec_list)

    def setup_mirror_modes(self):
        ''' prepare switch for bypass/tap mode
        '''
        # don't want any rx traffic from firewall tap interface
        dfs = DirectFlowSwitch.get_directflow_switch()
        logging.info('setup ACLs on SWITCH_INTERFACES_TO_FW_TAP')
        cmds = ['enable', 'configure',
                'mac access-list drop_all',
                'deny any any',
                'interface %s' % ','.join(config.SWITCH_INTERFACES_TO_FW_TAP),
                'mac access-group drop_all in']
        logging.info('Sending config cmds to switch: \n%s',
                     utils.format_cli_cmds_for_printing(cmds))
        dfs.exec_eapi_cmds(cmds)

        # setup DirectFlow mirror dest; put interface into mirroring mode state
        logging.info('Config mirroring dest on SWITCH_INTERFACES_TO_FW_TAP')
        cmds = ['enable', 'configure']
        for intf in config.SWITCH_INTERFACES_TO_FW_TAP:
            session_name = utils.scrub_mon_session_name(
                'DFLOW_MIRROR_TO_FW_TAP_%s' % intf)
            cmds.append('monitor session %s destination %s' %
                        (session_name, intf))
        cmds.append('end')
        logging.info('Sending config cmds to switch: \n%s',
                     utils.format_cli_cmds_for_printing(cmds))
        dfs.exec_eapi_cmds(cmds)

        if config.MIRROR_AFTER_REWRITES:
            mirror_action_type = 'egress mirror'
        else:
            mirror_action_type = 'ingress mirror'

        if (config.OPERATING_MODE == config.MIRROR_MODE and
                config.SWITCH_INTERFACES_TO_BE_MIRRORED):
            logging.info('Configuring mirror source interface flow entry')
            name = utils.scrub_flow_name(
                'MIRROR_TO_FW_TAP__%s_mirror_to:%s' % (
                    '_'.join(config.SWITCH_INTERFACES_TO_BE_MIRRORED),
                    '_'.join(config.SWITCH_INTERFACES_TO_FW_TAP)))
            mirror_intf = ','.join(config.SWITCH_INTERFACES_TO_BE_MIRRORED)
            intf_to_tap = ','.join(config.SWITCH_INTERFACES_TO_FW_TAP)
            fspec = {'name': name,
                     'priority': config.PRIORITY_STATIC_PORT_BINDING_FLOW,
                     'match': ['input interface %s' % mirror_intf],
                     'action': ['%s %s' % (mirror_action_type, intf_to_tap)]}
            dfs.add_flows([fspec])

        elif config.OPERATING_MODE == config.MIRROR_AND_SHUNT_MODE:
            logging.info('Creating combined static binding and mirror flows')
            flowspec_list = []
            for flow in MIRROR_AND_SHUNT_MODE_BYPASS_AND_MIRROR_FLOWS:
                name = utils.scrub_flow_name(
                    '%s__in:%s_out:%s_mirror_to:%s' % (
                        flow[0], flow[1], flow[2], flow[3]))
                fspec = {'name': name,
                         'priority': config.PRIORITY_STATIC_PORT_BINDING_FLOW,
                         'match': ['input interface %s' % flow[1]],
                         'action': ['output interface %s' % flow[2],
                                    '%s %s' % (mirror_action_type, flow[3])]}
                flowspec_list.append(fspec)

            for flow in MIRROR_AND_SHUNT_MODE_RETURN_STATIC_BINDING_FLOWS:
                name = utils.scrub_flow_name('%s__in:%s_out:%s' %
                                             (flow[0], flow[1], flow[2]))
                fspec = {'name': name,
                         'priority': config.PRIORITY_STATIC_PORT_BINDING_FLOW,
                         'match': ['input interface %s' % flow[1]],
                         'action': ['output interface %s' % flow[2]]}
                flowspec_list.append(fspec)
            dfs.add_flows(flowspec_list)

    def check_iptables(self):
        ''' check open ports
        '''
        # print ' checking iptables for open DFA ports:'
        # utils.exec_shell_cmd('sudo iptables -L | grep %d' % SYSLOG_PORT)
        cmd = "sudo iptables -L | egrep '%d'" % (config.SYSLOG_PORT)
        utils.exec_shell_cmd(cmd, echo=False)

    def close_ports(self, args):
        ''' close L4 ports used by DFA
        '''
        # to do: rewrite with while loop in case multiple entries to open same
        # port
        self.check_iptables()
        if config.SYSLOG_TRANSPORT == config.UDP:
            utils.exec_shell_cmd(config.CLOSE_SYSLOG_UDP_PORT_CMD)
        else:
            utils.exec_shell_cmd(config.CLOSE_SYSLOG_TCP_PORT_CMD)
        self.check_iptables()

    def mon(self, args):
        ''' shortcut to monitor
        '''
        return self.monitor(args)

    def monitor(self, args):
        ''' display flow entries in TCAM
        '''
        if not is_valid_dfa_installation():
            return 1
        dfs = self.directflow_switch(args)
        if dfs:
            dfs.start_monitoring_flows()

    def delete(self, args):
        ''' remove dynamic flow entries (drops, bypasses and redirects)
        '''
        if not is_valid_dfa_installation():
            return 1
        dfs = self.directflow_switch(args)
        if dfs:
            dfs.delete_dynamic_flows()

# hidden testing commands
    def delete_inactive(self, args):
        ''' hidden command: remove inactive (expired and rejected) flows
            from sysDB and running config
        '''
        self.directflow_switch(args).delete_inactive_flows()

    def inject_flows(self, args):
        ''' usage: assist inject_flows [num_flows]
        '''
        if len(args) > 0:
            num_flows = int(args[0])
        else:
            num_flows = 50
        print 'injecting %d flows...' % num_flows
        DirectFlowSwitch.inject_test_flows(num_flows, 'DROP_TEST')

# END hidden commands

    def directflow_switch(self, args):
        ''' returns object for accessing switch with DirectFlow support
        '''
        if len(args) == 0:
            return DirectFlowSwitch.get_directflow_switch()
        elif len(args) >= 3:
            if len(args) == 4:
                protocol = args[3]
            else:
                protocol = 'HTTPS'
            return DirectFlowSwitch.DirectFlowSwitch(
                args[0], args[1], args[2], protocol)
        else:
            print 'Error: incorrect number of command args'
            self.usage()

    def main(self):
        ''' start here
        '''
        if len(sys.argv) < 2:
            self.usage()
        else:
            cmd = sys.argv[1]
            if cmd in self.methods:
                args = sys.argv[2:]
                self.methods[cmd](args)
            else:
                for help_cmd in ['help', '-h', '--help', '?']:
                    if help_cmd in cmd:
                        return self.usage()
                print 'Unknown assist command: %s' % cmd
                self.usage()

    def usage(self):
        ''' usage
        '''
        usage =\
            ''' DirectFlow Assist - Command Line Processor:
 usage: assist <command> [options]

 Command            Description
 ------------------------------------------------------------------------
 start              Start DirectFlow Assist process
 stop               Stop DirectFlow Assist process
 status             Show multiple status elements for DFA
 monitor            Monitor active DirectFlow entries on switch
 delete             Delete DFA inserted DROP and BYPASS flows on switch
 setup              Initial setup of DFA static flows to/from the
                    attached firewall, create log file, etc.
 setup_start        Combined setup and start for cold starts from EOS
                    event-handler after reloads
 close_ports        Close UDP or TCP syslog listening port(s) in local
                    iptables (occasionally useful)

'''
        print usage


def is_valid_dfa_installation():
    ''' validate config file, eapi, eos ver
    '''
    try:
        return (has_valid_config_file() and
                have_eapi_access() and
                has_valid_eos_version())
    except Exception as ex:
        print ex.message
        return False


def have_eapi_access():
    ''' basic eapi check
    '''
    try:
        dfs = DirectFlowSwitch.get_directflow_switch()
        dfs.exec_eapi_cmds(['show privilege'])
        return True
    except Exception:
        raise Exception('ERROR: Unable to access eAPI, check EOS & DFA config')


def has_valid_eos_version():
    ''' verify minimum EOS version
    '''
    dfs = DirectFlowSwitch.get_directflow_switch()
    if dfs.eos_version_at_least(config.MIN_EOS_VERSION):
        return True
    else:
        print "DirectFlow Assist requires EOS %s or later" % config.MIN_EOS_VERSION
        logging.error("DirectFlow Assist requires EOS %s or later",
                      config.MIN_EOS_VERSION)
        return False


def has_valid_config_file():
    ''' verify that eapi and interface settings are in config file
        appropriate for operating mode:  SHUNT_MODE,
        INLINE_MODE, MIRROR_AND_SHUNT_MODE, MIRROR_MODE
    '''
    msg = ''
    if (config.SWITCH['eapi_protocol'] != 'unix-socket' and (
            not config.SWITCH['ip'] or
            not config.SWITCH['eapi_username'] or
            not config.SWITCH['eapi_password'])):
        msg = 'switch IP, username and/or password not configured in config.py'

    elif not config.ACCEPT_SYSLOG_MSGS_FROM_IP:
        msg = 'no IP addresses in ACCEPT_SYSLOG_MSGS_FROM_IP in config.py'

    elif ((config.OPERATING_MODE == config.MIRROR_AND_SHUNT_MODE or
           config.OPERATING_MODE == config.MIRROR_MODE) and
          not config.SWITCH_INTERFACES_TO_FW_TAP):
        msg = 'SWITCH_INTERFACES_TO_FW_TAP not configured in config.py'

    elif config.OPERATING_MODE == config.SHUNT_MODE and (
            not config.SWITCH_INTERFACE_A or
            not config.SWITCH_INTERFACE_AF or
            not config.FIREWALL_INTERFACE_AF or
            not config.SWITCH_INTERFACE_B or
            not config.SWITCH_INTERFACE_BF or
            not config.FIREWALL_INTERFACE_BF):
        msg = 'switch and firewall interfaces not configured in config.py'

    elif config.OPERATING_MODE == config.INLINE_MODE and (
            not config.SWITCH_INTERFACE_A or
            not config.SWITCH_INTERFACE_AF):
        msg = 'switch interface A and/or AF not configured in config.py'

    if msg:
        print 'ERROR: %s' % msg
        logging.error(msg)
        return False
    else:
        return True


def is_already_running():
    ''' if process id file exists DFA may already be running or did not
        shut down gracefully
    '''
    if util.pid_file_exists():
        print 'DFA pid file %s already exists' % util.pid_filename()
        if util.pid_process_running():
            print 'DFA process already running since pid is in /proc'
            return True
        else:
            print 'removing old DFA pid file'
            util.delete_pid_file()
    return False


def main():
    ''' it all starts here
    '''
    Assist().main()
