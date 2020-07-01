#!/usr/bin/env python2.7
#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = line-too-long

import sys
# sys.path.extend(['./persist_common', './persist_pan'])

import unittest
import logging
import config
from directflow_assist import PANSyslogMsg

ALLOW_MSG = '<14>Dec 31 23:59:59 PA-3020A.arista.com  : 1,2019/05/27 14:21:37,001801014991,TRAFFIC,start,1,2015/05/27 14:21:37,10.95.1.144,172.22.28.42,0.0.0.0,0.0.0.0,backup_flow_bypass_10m,,,ssh,vsys1,untrust,trust,ae1,ae2,DirectFlow_Assist,2015/05/27 14:21:37,51623,1,55215,22,0,0,0x0,tcp,allow,321,243,78,4,2015/05/27 14:21:29,0,any,0,2249869,0x0,10.0.0.0-10.255.255.255,172.16.0.0-172.31.255.255,0,3,1,n/a'
DENY_MSG = 'Dec 31 23:59:59 PA-5050 1,2018/02/12 15:10:06,0009C103236,THREAT,virus,1,2015/02/12 15:10:06,188.40.238.250,10.128.50.2,0.0.0.0,0.0.0.0,rule2,,,web-browsing,vsys1,vwire1-untrust,vwire1-trust,ethernet1/2,ethernet1/1,Threat log fws to Arista,2015/02/12 15:10:06,33606445,1,80,45608,0,0,0x0,tcp,deny,"eicar.com",Eicar Test File(100000),any,medium,server-to-client,222,0x0,DE,10.0.0.0-10.255.255.255,0,,0,,'


class TestPANSyslogMsg(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_validate_config_syslog_field_labels(self):
        self.assertTrue('TRAFFIC' in config.PAN_SYSLOG_FIELD_LABELS)
        self.assertTrue('THREAT' in config.PAN_SYSLOG_FIELD_LABELS)
        self.assertGreater(len(config.PAN_SYSLOG_FIELD_LABELS['TRAFFIC']), 40)
        self.assertGreater(len(config.PAN_SYSLOG_FIELD_LABELS['THREAT']), 40)

    def test_allow_syslog_msg(self):
        psm = PANSyslogMsg.PANSyslogMsg(ALLOW_MSG)
        self.assertTrue(psm.is_valid())
        self.assertEqual(psm.action, 'allow')
        self.assertEqual(psm.type, 'TRAFFIC')
        self.assertEqual(psm.sub_type, 'start')
        self.assertEqual(psm.protocol, 'tcp')
        self.assertEqual(psm.src_ip, '10.95.1.144')
        self.assertEqual(psm.src_port, '55215')
        self.assertEqual(psm.in_intf, 'ae1')
        self.assertEqual(psm.dst_ip, '172.22.28.42')
        self.assertEqual(psm.dst_port, '22')
        self.assertEqual(psm.out_intf, 'ae2')

    def test_deny_syslog_msg(self):
        psm = PANSyslogMsg.PANSyslogMsg(DENY_MSG)
        self.assertTrue(psm.is_valid())
        self.assertEqual(psm.action, 'deny')
        self.assertEqual(psm.type, 'THREAT')
        self.assertEqual(psm.sub_type, 'virus')
        self.assertEqual(psm.protocol, 'tcp')
        self.assertEqual(psm.src_ip, '188.40.238.250')
        self.assertEqual(psm.src_port, '80')
        self.assertEqual(psm.dst_ip, '10.128.50.2')
        self.assertEqual(psm.dst_port, '45608')


if __name__ == '__main__':
    unittest.main()
