#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = line-too-long

import sys
# sys.path.extend(['./persist_common', './persist_chkp'])

import unittest
import logging
from directflow_assist import CheckPointSyslogMsg

# Test data
MSG1 = '<85>Dec 31 19:19:03+22:00 192.168.133.152 Action="accept" UUid="{0x54ec76ff,0x0,0x9885a8c0,0xc0000000}" rule="1" rule_uid="{37033D07-DF90-4AEB-B70D-A1D5E56BA70E}" service_id="ssh_DFA" src="192.168.133.1" dst="192.168.133.152" proto="6" product="VPN-1 & FireWall-1" service="22" s_port="63316" product_family="Network"'
SSH = 22


class TestCheckPointSyslogMsg(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_parse_syslog_msg(self):
        psm = CheckPointSyslogMsg.CheckPointSyslogMsg(MSG1)
        self.assertEqual(psm.action, 'accept')
        self.assertEqual(psm.protocol, 'TCP')
        self.assertEqual(psm.src_ip, '192.168.133.1')
        self.assertEqual(psm.src_port, '63316')
        self.assertEqual(psm.dst_ip, '192.168.133.152')
        self.assertEqual(psm.dst_port, str(SSH))
        self.assertTrue(psm.is_valid())


if __name__ == '__main__':
    unittest.main()
