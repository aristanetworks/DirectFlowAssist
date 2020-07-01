#!/usr/bin/env python2.7
#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = line-too-long

import sys

import unittest
from mock import Mock, patch
from directflow_assist import FlowAssistController


DROP_MSG = '<10>May 12 16:30:37 PA-3020A.arista.com  : 1,2019/05/12 16:30:36,001801014991,THREAT,flood,1,2015/05/12 16:30:36,10.95.1.144,172.22.28.43,0.0.0.0,0.0.0.0,Attack_on_linux4,,,not-applicable,vsys1,,,,,DirectFlow_Assist,2015/05/12 16:30:36,0,6,0,0,0,0,0x0,hopopt,drop,"",Session Limit Event(8801),any,critical,client-to-server,6674,0x0,10.0.0.0-10.255.255.255,172.16.0.0-172.31.255.255,0,,0,,,0,,,,,,,,0'
DROP_FLOW_SPEC = [{'name': 'DROP_Session_L_HOPOPT_10-95-1-144_172-22-28-43_fake_time', 'idle_time': 300, 'persistent': False, 'priority': 50, 'action': ['drop'], 'lifetime': 1800, 'match': ['source ip 10.95.1.144', 'destination ip 172.22.28.43']}]

BYPASS_MSG = '<14>May 12 20:12:04 PA-3020A.arista.com  : 1,2019/05/12 20:12:04,001801014991,TRAFFIC,start,1,2015/05/12 20:12:04,172.22.29.191,172.22.28.42,0.0.0.0,0.0.0.0,backup_flow_bypass_10m,,,ping,vsys1,untrust,trust,ae1,ae2,DirectFlow_Assist,2015/05/12 20:12:04,228164,2,0,0,0,0,0x0,icmp,allow,362,362,0,2,2015/05/12 20:11:47,0,any,0,2215099,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,2,0,n/a'
BYPASS_FLOW_SPEC = [{'name': 'BYPASS_FW_ping_ICMP_172-22-29-191_172-22-28-42_fake_time_INI', 'idle_time': 300, 'persistent': False, 'priority': 40, 'action': ['output interface Po20'], 'lifetime': 600, 'match': ['input interface Po10', 'source ip 172.22.29.191', 'destination ip 172.22.28.42', 'ip protocol icmp']}, {'name': 'BYPASS_FW_ping_ICMP_172-22-28-42_172-22-29-191_fake_time_RSP', 'idle_time': 300, 'persistent': False, 'priority': 40, 'action': ['output interface Po10'], 'lifetime': 600, 'match': ['input interface Po20', 'destination ip 172.22.29.191', 'source ip 172.22.28.42', 'ip protocol icmp']}]


class TestFlowAssistController(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_process_msg_bypass(self):
        FlowAssistController.FW_SWITCH_INTF_MAP = {'ae1': ['Po10', 'Po20'], 'ae2': ['Po20', 'Po10']}
        FlowAssistController.utils.ts_date = Mock(return_value='fake_time')
        self.controller = FlowAssistController.FlowAssistController()
        self.controller.directflow_switch.add_flows = Mock()
        self.controller.process_msg(BYPASS_MSG)
        self.controller.directflow_switch.add_flows.assert_called_with(BYPASS_FLOW_SPEC)

    def test_process_msg_drop(self):
        # FlowAssistController.FW_SWITCH_INTF_MAP = {'ae1': ['Po10', 'Po20'], 'ae2': ['Po20', 'Po10']}
        FlowAssistController.utils.ts_date = Mock(return_value='fake_time')
        self.controller = FlowAssistController.FlowAssistController()
        self.controller.directflow_switch.add_flows = Mock()
        self.controller.process_msg(DROP_MSG)
        self.controller.directflow_switch.add_flows.assert_called_with(DROP_FLOW_SPEC)


if __name__ == '__main__':
    unittest.main()
