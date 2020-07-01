#!/usr/bin/env python2.7
#
# Copyright (c) 2014-2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = unused-argument

''' main entry point for DirectFlow Assist demo
'''

from common import utils
import DemoController
import config
import app


class AssistDemo(app.Assist, object):
    ''' main entry point for DirectFlow Assist demo
    '''
    def __init__(self):
        super(AssistDemo, self).__init__()

    def run_demo(self, args):
        ''' start demo
        '''
        if not app.has_valid_config_file():
            return
        dmc = DemoController.DemoController()
        dmc.startup()

    def close_ports(self, args):
        ''' close L4 port in iptables
        '''
        utils.exec_shell_cmd(config.CLOSE_DEMO_CTRL_PORT_CMD)
        super(AssistDemo, self).close_ports(args)

    def check_iptables(self):
        ''' check iptables for open DirectFlow Assist ports
        '''
        print 'check iptables for open DirectFlow Assist ports:'
        cmd = "sudo iptables -L | egrep '%d|%d'" % (config.SYSLOG_PORT,
                                                    config.DEMO_CTRL_UDP_PORT)
        utils.exec_shell_cmd(cmd, echo=False)

    def usage(self):
        ''' usage
        '''
        usage =\
            ''' DirectFlow Assist - Command Line Processor:
 usage: assist <command> [options]

 Commands    Options                    Description
 -----------------------------------------------------------------------------
 run_demo    none                  Start in demo mode (listens for pause,
                                   resume & delete commands from DemoRemote)
 stop        none                  Stop DirectFlow Assist process on switch
 status      none                  Show assist process and open ports (local)
 setup       none                  Initial setup of static flows to/from the
                                   attached firewall, create log file, etc.
 setup_run   none                  Combined setup & run for cold starts such
                                   as from EOS event-handler after reloads
 close_ports none                  Close syslog listening port(s) in local
                                   iptables (in case of abnormal termination)
 monitor     [sw_IP user passwd]   Monitor flows on switch (local or remote)
 delete      [sw_IP user passwd]   Delete DROP and BYPASS flow entries on
                                    switch (local or remote) '''
        print usage


def main():
    ''' main
    '''
    AssistDemo().main()
