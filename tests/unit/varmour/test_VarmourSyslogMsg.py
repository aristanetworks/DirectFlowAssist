#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = line-too-long

import sys
# sys.path.extend(['./persist_common', './persist_chkp'])

import unittest
import logging
from directflow_assist import VarmourSyslogMsg

# Test data
PERMIT_MSG = 'Dec 31 23:59:59 000 vArmour va_syslog: [Chassis(vArmour):Device(4):VA_APP_ANET_RTLOG] sip=44.1.1.54 sport=47298 dip=44.1.1.55 dport=22 proto=6 c2s-pkts=10 s2c-pkts=11 sess-close-reason=policy-permit c2s-bytes=1849 s2c-bytes=1809 sintf=xe-4/0/4 dintf=xe-4/0/5'
DENY_MSG = 'Dec 31 23:59:59 000 vArmour va_syslog: [Chassis(vArmour):Device(4):VA_APP_ANET_RTLOG] sip=44.1.1.55 sport=35813 dip=44.1.1.54 dport=23 proto=6 c2s-pkts=0 s2c-pkts=0 sess-close-reason=policy-deny c2s-bytes=0 s2c-bytes=0 sintf=xe-4/0/5 dintf=xe-4/0/4'


class TestVarmourSyslogMsg(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_permit_syslog_msg(self):
        psm = VarmourSyslogMsg.VarmourSyslogMsg(PERMIT_MSG)
        self.assertTrue(psm.is_valid())
        self.assertEqual(psm.action, 'policy-permit')
        self.assertEqual(psm.type, VarmourSyslogMsg.VARMOUR)
        self.assertEqual(psm.protocol, 'TCP')
        self.assertEqual(psm.src_ip, '44.1.1.54')
        self.assertEqual(psm.src_port, '47298')
        self.assertEqual(psm.in_intf, 'xe-4/0/4')
        self.assertEqual(psm.dst_ip, '44.1.1.55')
        self.assertEqual(psm.dst_port, '22')
        self.assertEqual(psm.out_intf, 'xe-4/0/5')

    def test_deny_syslog_msg(self):
        psm = VarmourSyslogMsg.VarmourSyslogMsg(DENY_MSG)
        self.assertTrue(psm.is_valid())
        self.assertEqual(psm.action, 'policy-deny')
        self.assertEqual(psm.type, VarmourSyslogMsg.VARMOUR)
        self.assertEqual(psm.protocol, 'TCP')
        self.assertEqual(psm.src_ip, '44.1.1.55')
        self.assertEqual(psm.src_port, '35813')
        self.assertEqual(psm.in_intf, 'xe-4/0/5')
        self.assertEqual(psm.dst_ip, '44.1.1.54')
        self.assertEqual(psm.dst_port, '23')
        self.assertEqual(psm.out_intf, 'xe-4/0/4')


if __name__ == '__main__':
    unittest.main()
