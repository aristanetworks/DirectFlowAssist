#!/usr/bin/env python2.7
#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.

import sys
# sys.path.extend(['./persist_common', './persist_pan'])

import unittest
from mock import Mock, patch
from directflow_assist import DirectFlowSwitch

# move to fixture text files
SHOW_PLATFORM_TRIDENT_TCAM_4_14_6 = '''
=== TCAM summary for switch Linecard0/0 ===
TCAM group 6 uses 26 entries and can use up to 358 more.
  Mlag control traffic uses 4 entries.
  L3 Control Priority uses 14 entries.
  IGMP Snooping Flooding uses 8 entries.
TCAM group 11 uses 6 entries and can use up to 506 more.
  OpenFlow uses 6 entries.
TCAM group 7 uses 37 entries and can use up to 347 more.
  ACL Management uses 10 entries.
  L2 Control Priority uses 9 entries.
  Storm Control Management uses 2 entries.
  L3 Routing uses 16 entries.
TCAM group 23 uses 4 entries and can use up to 1020 more.
  Storm Control Port Rules uses 4 entries.'''

SHOW_PLATFORM_TRIDENT_TCAM_4_15_0 = '''
=== TCAM summary for switch Linecard0/0 ===
TCAM group 10 uses 38 entries and can use up to 1498 more.
  ACL Management uses 10 entries.
  L2 Control Priority uses 9 entries.
  Storm Control Management uses 2 entries.
  ARP Inspection uses 1 entries.
  L3 Routing uses 16 entries.
TCAM group 14 uses 8 entries and can use up to 1528 more.
  DirectFlow uses 8 entries.
TCAM group 9 uses 37 entries and can use up to 1499 more.
  Mlag control traffic uses 4 entries.
  CVX traffic uses 6 entries.
  L3 Control Priority uses 19 entries.
  IGMP Snooping Flooding uses 8 entries.
TCAM group 19 uses 3 entries and can use up to 1021 more.
  MLAG uses 3 entries.'''

SHOW_PLATFORM_TRIDENT_TCAM_NO_DIRECTFLOW = '''
=== TCAM summary for switch Linecard0/0 ===
TCAM group 10 uses 38 entries and can use up to 1498 more.
  ACL Management uses 10 entries.
  L2 Control Priority uses 9 entries.
  Storm Control Management uses 2 entries.
  ARP Inspection uses 1 entries.
  L3 Routing uses 16 entries.
TCAM group 9 uses 37 entries and can use up to 1499 more.
  Mlag control traffic uses 4 entries.
  CVX traffic uses 6 entries.
  L3 Control Priority uses 19 entries.
  IGMP Snooping Flooding uses 8 entries.
TCAM group 19 uses 3 entries and can use up to 1021 more.
  MLAG uses 3 entries.'''


class TestDirectFlowSwitch(unittest.TestCase):

    def setUp(self):
        # self.cli_no_cmd = open(get_fixture('show_platform_.text')).read()
        pass

    def tearDown(self):
        pass

    def test_parse_tcam_stats_directflow_disabled(self):
        (used, avail, utilization) = DirectFlowSwitch.parse_tcam_stats(
            SHOW_PLATFORM_TRIDENT_TCAM_NO_DIRECTFLOW)
        self.assertEqual(used, None)
        self.assertEqual(avail, None)
        self.assertEqual(utilization, None)

    def test_parse_tcam_stats_eos_4_14(self):
        (used, avail, utilization) = DirectFlowSwitch.parse_tcam_stats(
            SHOW_PLATFORM_TRIDENT_TCAM_4_14_6)
        self.assertEqual(used, 6)
        self.assertEqual(avail, 506)
        self.assertEqual(utilization, 1)

    def test_parse_tcam_stats_eos_4_15(self):
        (used, avail, utilization) = DirectFlowSwitch.parse_tcam_stats(
            SHOW_PLATFORM_TRIDENT_TCAM_4_15_0)
        self.assertEqual(used, 8)
        self.assertEqual(avail, 1528)
        self.assertEqual(utilization, 1)

    def test_add_flows(self):
        fspec = dict(name='test_flow', priority=99, persistent=False,
                     idle_time=120, lifetime=600,
                     match=['input interface e1', 'source ip 1.2.3.4'],
                     action=['output interface e2', 'set cos 2'])
        eapi_call_args = ['enable', 'configure', 'directflow', 'no shutdown',
                          'flow test_flow', 'action output interface e2',
                          'action set cos 2', 'match input interface e1',
                          'match source ip 1.2.3.4', 'priority 99',
                          'timeout hard 600', 'timeout idle 120',
                          'no persistent', 'end']
        dfs = DirectFlowSwitch.get_directflow_switch()
        dfs.exec_eapi_cmds = Mock(spec=DirectFlowSwitch, return_value=[{}])
        dfs.add_flows([fspec])
        dfs.exec_eapi_cmds.assert_called_with(eapi_call_args)

    def test_delete_flows(self):
        flow_names = ['flow1', 'flow2']
        eapi_call_args = ['enable', 'configure', 'directflow',
                          'no flow flow1', 'no flow flow2']
        dfs = DirectFlowSwitch.get_directflow_switch()
        dfs.exec_eapi_cmds = Mock(spec=DirectFlowSwitch)
        dfs.delete_flows(flow_names)
        dfs.exec_eapi_cmds.assert_called_with(eapi_call_args)

    def test_delete_dynamic_flows(self):
        active_flows = [{'name': 'DROP_flow'},
                        {'name': 'BYPASS_flow'},
                        {'name': 'REDIR_TO_FW_flow'},
                        {'name': 'STATIC_flow'}]  # make sure this one NOT deleted
        eapi_call_args = ['enable', 'configure', 'directflow',
                          'no flow DROP_flow',
                          'no flow BYPASS_flow',
                          'no flow REDIR_TO_FW_flow']
        sys.stdout = Mock()    # suppress print output for this test
        dfs = DirectFlowSwitch.get_directflow_switch()
        dfs.get_active_flows = Mock(return_value=active_flows)
        dfs.exec_eapi_cmds = Mock()
        dfs.delete_dynamic_flows()
        dfs.exec_eapi_cmds.assert_called_with(eapi_call_args)


if __name__ == '__main__':
    unittest.main()
