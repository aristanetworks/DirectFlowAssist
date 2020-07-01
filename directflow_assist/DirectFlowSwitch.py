#!/usr/bin/env python2.7
#
# Copyright (c) 2013-2015 Arista Networks, Inc.  All rights reserved
# Arista Networks, Inc. Confidential and Proprietary.

''' Class for interacting with an Arista Switch that supports DirectFlow
'''

import re
import time
import socket
import logging
import random
import config
from . import util
from .__init__ import __version__
from directflow_assist.common import arista
from directflow_assist.common import utils


TEST_MODE = False
DYNAMIC_FLOWNAME_PREFIXES = [config.DROP_FLOWNAME_PREFIX, config.BYPASS_FLOWNAME_PREFIX,
                             config.REDIR_FLOWNAME_PREFIX]


def get_directflow_switch():
    ''' convenience function; returns a DirectFlowSwitch object using
        ip and credentials from config.py
    '''
    # ToDo: check for EOS daytona image, use unix domain socket (local eAPI)
    # if SWITCH['ip'] = '127.0.0.1' or SWITCH['ip'] = 'localhost':
    #     return DirectFlowSwitch(None, None, None, protocol='UNIX')
    # else:
    return DirectFlowSwitch(config.SWITCH['ip'], config.SWITCH['eapi_username'],
                            config.SWITCH['eapi_password'],
                            config.SWITCH['eapi_protocol'])


class DirectFlowSwitch(arista.AristaEOS):
    ''' An Arista Networks switching platform that supports the DirectFlow
        EOS feature
    '''
    def __init__(self, switch_ip, username, passwd, protocol):
        super(DirectFlowSwitch, self).__init__(switch_ip, username, passwd,
                                               protocol)

    def add_flows(self, flowspec_list):
        ''' Add flows to running-config on switch
        '''
        cmds = _translate_flowspecs(flowspec_list)
        if len(cmds) < 100:   # filter out large test batches
            logging.info('Sending flow config cmds to switch: %s \n%s',
                         self.switch_ip,
                         utils.format_cli_cmds_for_printing(cmds))
        else:
            logging.info('Sending %d flow config cmds to switch', len(cmds))
        if TEST_MODE:
            print 'TEST_MODE: %s, not sending config commands to switch' % TEST_MODE
            return
        # start_ts= time.time()
        resp = self.exec_eapi_cmds(cmds)
        # finish_ts= time.time()
        # print ' eAPI latency: %.5f' % ( finish_ts - start_ts )
        if arista.is_empty_eapi_response(resp):
            logging.info('success, switch response is empty')
        else:
            logging.info('switch response: \n%s', utils.unpack(resp, show_type=True))

    def delete_flows(self, flow_names):
        ''' delete flows
        '''
        if not flow_names:
            return
        cmds = ['enable', 'configure', 'directflow']
        for flow_name in flow_names:
            cmds.append('no flow %s' % flow_name)
        self.exec_eapi_cmds(cmds)

    def delete_dynamic_flows(self, name_startswith=None):
        ''' remove flow from running config on switch if name starts with
            one of the passed prefixes
        '''
        if not name_startswith:
            name_startswith = DYNAMIC_FLOWNAME_PREFIXES  # defaults
        elif not isinstance(name_startswith, list):
            name_startswith = [name_startswith]
        else:
            name_startswith = name_startswith
        print ('\nDeleting flows on switch %s with names that begin with %s'
               % (self.switch_ip, name_startswith))
        flows = self.get_active_flows()
        flow_names = [flow['name'] for flow in flows]
        if len(flow_names) == 0:
            print 'No flows on switch \n'
            return
        remove_flows = []
        for fname in flow_names:
            for name_prefix in name_startswith:
                if fname.startswith(name_prefix):
                    remove_flows.append(fname)
        if len(remove_flows) == 0:
            print 'No flownames starting with %s to be removed' % name_startswith
            return
        elif len(remove_flows) <= config.MONITOR_FLOWS_MAX_DISPLAY:
            for fname in remove_flows:
                print '  REMOVING: %s' % fname
        self.delete_flows(remove_flows)

    def delete_inactive_flows(self):
        ''' delete inactive directflow entries from sysDB and running config
        '''
        inactive_flownames = self.get_inactive_flownames()
        if inactive_flownames:
            logging.debug('purging %d inactive directflow entries on switch',
                          len(inactive_flownames))
            self.delete_flows(inactive_flownames)

    def get_flows_in_running_config(self):
        ''' returns all flow names in running-config
            Note: this will include active and possibly inactive flows
        '''
        cmds = ['enable', 'show running-config | grep flow']
        # sh run unconverted in 4.13
        resp = self.exec_eapi_cmds(cmds, output_format='text')
        # extract flow entry names from show run text output
        raw = str(resp[1]['output'])
        if raw.startswith('directflow'):
            raw = raw.replace('directflow', '', 1)
        flows_list = raw.split('\n')
        flow_names = []
        for flow in flows_list:
            flow = flow.strip()
            if flow.startswith('flow '):
                flow = flow.replace('flow ', '', 1)
                if len(flow) > 0:
                    flow_names.append(flow)
        return flow_names

    def get_active_flows(self):
        ''' returns active directflow (in TCAM) entries
            Note: running-config MAY contain flow definitions that were NOT
            accepted by the DIRECTFLOW agent or that have timed out/expired
        '''
        resp = self.exec_eapi_cmds(['show directflow flows'])
        # logging.debug('get_active_flows resp: %s' % resp )
        flows = resp[0]['flows']
        return flows

    def get_inactive_flownames(self):
        ''' returns names of flows that are in running config and sysDB
            but not programmed into TCAM; usually from flows with
            timeouts that have expired and rejected flows
        '''
        inactive_flows_status = ('Flow not programmed',
                                 'Flow rejected due to insufficient resources')
        cmds = ['show directflow detail']    # requires EOS 4.14.0F or later
        resp = self.exec_eapi_cmds(cmds)
        # print utils.unpack(resp)
        flows = resp[0]['details']['status']
        inactive_flownames = []
        for flowname, status in flows.items():
            # print '%s, status: %s' % (flowname,status)
            if status in inactive_flows_status:
                inactive_flownames.append(flowname)
        return inactive_flownames

    def start_monitoring_flows(self, refresh=config.MONITOR_FLOWS_REFRESH_DEFAULT):
        ''' Reports on active directflow flow entries on switch.
            refresh in seconds.  Never returns.
        '''
        print 'Monitoring active DirectFlow entries for switch: %s' % self.switch_ip
        try:
            if self.switch_ip == 'localhost' or self.switch_ip == '127.0.0.1':
                switch_name = socket.gethostname()
            else:
                switch_name = self.switch_ip
            while True:
                tcam = self.tcam_directflow_utilization()
                flows = self.get_active_flows()
                num_flows = len(flows)
                print ('\nSw: %s  v%s  Assist=%s  #Flows: %s  TCAM: %s%%'
                       '  Refresh: %ds, %s'
                       % (switch_name[:16].ljust(14),
                          __version__,
                          'RUN' if util.pid_process_running() else 'OFF',
                          str(num_flows).ljust(4),
                          tcam['pct_used'] if tcam else 'NA',
                          refresh,
                          utils.ts_date(with_year=False, ms_prec=0)))

                limit_msg = ''
                if num_flows > config.MONITOR_FLOWS_MAX_DISPLAY:
                    limit_msg = ('[displaying first %s flows]'
                                 % config.MONITOR_FLOWS_MAX_DISPLAY)
                print 'Flow Name  %s  Matched  Pri  Hard|Idle' % limit_msg.ljust(66)
                print '-' * 102
                for flow in flows[0:config.MONITOR_FLOWS_MAX_DISPLAY]:
                    print ('%s%s%s%s' % (flow['name'].ljust(80),
                                         str(flow['matchPackets']).ljust(10),
                                         str(flow['priority']).ljust(4),
                                         str(flow['hardTimeout']) + '|' +
                                         str(flow['idleTimeout'])))
                time.sleep(refresh)
        except KeyboardInterrupt:
            print 'bye'
        # except Exception:
        #    print 'Error: %s' % sys.exc_value
        #    # traceback.print_exc()

    def tcam_directflow_utilization(self):
        ''' returns tuple with DirectFlow TCAM space statistics
            ( #_entries_used, #_entries_avail, utilized% ) tuple
            Note: entries used includes 4 entries reserved by EOS
            for feature interaction and 4 static entries used by DFA
            for traffic steering to/from firewall
        '''
        cmds = ['enable', 'show platform trident tcam']
        resp = self.exec_eapi_cmds(cmds, output_format='text')
        tcam_stats = resp[1]['output']
        # print tcam_stats
        (used, avail, utilization) = parse_tcam_stats(tcam_stats)
        return {'pct_used': utilization, 'num_used': used, 'num_avail': avail}


def parse_tcam_stats(tcam_stats):
    ''' parse EOS 'show platform trident tcam' text output
    samples:
        4.14.6
          TCAM group 11 uses 6 entries and can use up to 506 more.
            OpenFlow uses 6 entries.
        4.15.0
          TCAM group 14 uses 8 entries and can use up to 1528 more.
            DirectFlow uses 8 entries.
        Note: group number changes and OpenFlow vs DirectFlow name
    '''
    regex = (r'TCAM group \d{1,3} uses (\d{1,6}) entries and can use up to '
             r'(\d{1,6}) more.\s+(OpenFlow|DirectFlow)')

    match_obj = re.search(regex, tcam_stats)
    if not match_obj:
        logging.debug('no regex match for TCAM stats in show platform output')
        return (None, None, None)
    else:
        used = int(match_obj.group(1))
        avail = int(match_obj.group(2))
        utilization = int(round(used / float(used + avail) * 100))
        return (used, avail, utilization)


def _translate_flowspecs(flow_specs):
    ''' translate flowspec to EOS config commands
    '''
    cmds = ['enable',
            'configure',
            'directflow',
            'no shutdown']          # ensure directflow feature enabled
    for fspec in flow_specs:
        # logging.debug('Preparing to inject Flow_Spec: \n%s',
        #              utils.unpack(fspec))
        cmds.append('flow %s' % fspec['name'])

        for act in fspec['action']:
            cmds.append('action %s' % act)

        for match in fspec['match']:
            cmds.append('match %s' % match)

        if 'priority' in fspec:
            cmds.append('priority %s' % fspec['priority'])

        if 'lifetime' in fspec:
            cmds.append('timeout hard %d' % fspec['lifetime'])

        if 'idle_time' in fspec:
            cmds.append('timeout idle %d' % fspec['idle_time'])

        if 'persistent' in fspec and fspec['persistent'] is False:
            cmds.append('no persistent')  # EOS default is 'persistent'

        if 'comment' in fspec:
            cmds.append(fspec['comment'])
    cmds.append('end')
    # all flow entries are persistent in 4.13
    # cmds.append('copy running-config startup-config')
    return cmds


def is_dfa_static_flow(flow_name):
    ''' check flow name
    '''
    return flow_name.startswith(config.STATIC_BINDING_FLOWNAME_PREFIX)


def is_dfa_dynamic_flow(flow_name):
    ''' returns True if flow_name prefix is in DYNAMIC_FLOWNAME_PREFIXES
    '''
    for prefix in DYNAMIC_FLOWNAME_PREFIXES:
        if flow_name.startswith(prefix):
            return True
    return False


def gen_ip_addresses(max_addrs):
    ''' generator for a sequence of ip addresses
    '''
    ip_a = 10
    ip_b = random.randint(1, 254)

    num_ip_addrs = 0
    for ip_c in range(1, 255):
        for ip_d in range(1, 255):
            src_ip = '%s.%s.%s.%s' % (ip_a, ip_b, ip_c, ip_d)
            yield src_ip
            num_ip_addrs += 1
            if num_ip_addrs >= max_addrs:
                return


def inject_test_flows(num_flows, flow_name_prefix):
    ''' unit test helper
    '''
    utils.setup_logging(config.LOG_FILE, config.MIN_LOG_LEVEL)
    dst_ip = '2.3.4.5'
    src_port = 50000
    dst_port = 80
    protocol = 'TCP'
    dfs = get_directflow_switch()
    flow_specs = []
    ip_addr = gen_ip_addresses(num_flows)
    for _ in range(num_flows):
        src_ip = ip_addr.next()
        name = ('%s__%s_%s:%s_%s:%s_INIT' %
                (flow_name_prefix, protocol, src_ip, src_port, dst_ip,
                 dst_port))
        name = utils.scrub_flow_name(name)
        flow_spec = {
            'name': name,
            'match': ['input interface e1',
                      'source ip %s' % src_ip,
                      'destination ip %s' % dst_ip,
                      'source port %s' % src_port,
                      'destination port %s' % dst_port,
                      'ip protocol %s' % protocol],
            'action': ['drop'],
            'priority': 100,
            'lifetime': 120}
        flow_specs.append(flow_spec)
    logging.info('Injecting %d test directflow entries', len(flow_specs))
    dfs.add_flows(flow_specs)


def test():
    ''' unit test
    '''
    # inject_test_flows(1000, 'MAX_FLOWS_TEST')
    dfsw = DirectFlowSwitch('bizdev-7050s', 'eapi', 'eapi', protocol='HTTPS')
    dfsw.delete_inactive_flows()

if __name__ == "__main__":
    test()
