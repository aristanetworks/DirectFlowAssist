#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = line-too-long

import sys
# sys.path.extend(['./persist_common', './persist_fnet'])

import unittest
import logging
from directflow_assist import FortigateSyslogMsg

# Test data
MSG1 = '<13>date=2018-02-04 time=15:00:12 devname=FortiGate-500D devid=FGT5HD3914800308 logid=0000000015 type=traffic subtype=forward level=notice vd=FWTest srcip=172.22.28.190 srcport=53072 srcintf="port11" dstip=172.22.28.48 dstport=5989 dstintf="port12" poluuid=8bbd7af0-acbd-51e4-4cb0-a4a3a4e0a960 sessionid=28755 action=start policyid=1 dstcountry="Reserved" srccountry="Reserved" trandisp=noop service="tcp/5989" proto=6 duration=0 sentbyte=0 rcvdbyte=0'


class TestFortigateSyslogMsg(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_parse_syslog_msg(self):
        psm = FortigateSyslogMsg.FortigateSyslogMsg(MSG1)
        self.assertTrue(psm.is_valid())
        self.assertEqual(psm.type, 'traffic')
        self.assertEqual(psm.action, 'start')
        self.assertEqual(psm.protocol, 'TCP')
        self.assertEqual(psm.src_ip, '172.22.28.190')
        self.assertEqual(psm.src_port, '53072')
        self.assertEqual(psm.dst_ip, '172.22.28.48')
        self.assertEqual(psm.dst_port, '5989')


if __name__ == '__main__':
    unittest.main()
