#!/usr/bin/env python2.7
#
# Copyright (c) 2014-2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = too-many-instance-attributes, line-too-long

''' Parses syslog messages from a Check Point Firewall
'''

import logging
import re
import config
from directflow_assist.common import utils
from .SyslogMsg import SyslogMsg, scrub_app_name, tokenize_msg, dump_dict_sorted

TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M:%S'
CONVERT_TO_UTC = False
VALID_INTERFACE_TYPES = ['eth']


class CheckPointSyslogMsg(SyslogMsg):
    ''' Parses syslog messages from Check Point Firewalls
    '''
    def __init__(self, raw_msg, *args, **kwargs):
        super(CheckPointSyslogMsg, self).__init__(raw_msg, *args, **kwargs)

    def get_timestamp_format(self):
        return TIMESTAMP_FORMAT

    def preprocess_raw_msg(self):
        ''' preprocess
        '''
        msg = self.raw_msg.strip()  # remove leading and trailing whitespace
        # remove leading <NN> prefix if present
        mobj = re.match(r'(<\d{1,6}>)?(.*)', msg)
        return mobj.group(2)

    def parse_msg(self):
        ''' parse
        '''
        msg_string = self.preprocess_raw_msg()
        for token in tokenize_msg(msg_string):
            key, value = token.split('=')
            self.msg_dict[key] = value.strip('"')

        self.timestamp = utils.extract_iso8601_timestamp(
            msg_string, CONVERT_TO_UTC, TIMESTAMP_FORMAT)
        self.in_intf = self.msg_dict.get('srcintf', None)
        self.out_intf = self.msg_dict.get('dstintf', None)
        self.src_ip = self.msg_dict.get('src', None)
        self.src_port = self.msg_dict.get('s_port', '0')
        self.dst_ip = self.msg_dict.get('dst', None)
        self.dst_port = self.msg_dict.get('service', '0')
        protocol = self.msg_dict.get('proto', 'unknown')
        self.protocol = utils.IP_PROTOCOL.get(protocol, protocol)
        app = self.msg_dict.get('service_id', 'unknown')
        self.app = scrub_app_name(app)
        self.type = self.msg_dict.get('product', 'unknown')
        if 'Action' in self.msg_dict:
            self.action = self.msg_dict.get('Action')
        return True

    def decoded_msg(self):
        ''' return parsed msg
        '''
        return dump_dict_sorted(self.msg_dict)

    def validate_msg(self):
        ''' override for special case with Check Point syslog msgs, where
            service_id (aka application) field suffix indicates if DFA
            should assist
        '''
        service_id = self.msg_dict.get('service_id', '')
        if not service_id.endswith(config.ASSIST_WHEN_SERVICE_ID_SUFFIX):
            logging.debug('chkp fw syslog msg, service_id: %s  suffix not: %s',
                          service_id, config.ASSIST_WHEN_SERVICE_ID_SUFFIX)
            self.valid_msg = False    # not req'd as False is default
        else:
            super(CheckPointSyslogMsg, self).validate_msg()

    def validate_intf(self, intf):
        ''' validate CheckPoint FW interface
        '''
        if intf:
            regex = r'^\s*([A-Za-z\-]+).*'
            mobj = re.match(regex, intf)
            if mobj:
                intf_type = mobj.group(1)
                if intf_type in VALID_INTERFACE_TYPES:
                    return
        logging.warning('CheckPointSyslogMsg: invalid interface [%s] ', intf)
        self.valid_msg = False


# ----------------------------------------------------------------------------

def test():
    ''' test msg decoding
    '''
    # to run test:
    # PYTHONPATH=$PYTHONPATH:../persist_common:../persist_chkp
    # python CheckPointSyslogMsg.py
    syslog_msgs = [
        '<85>Mar 05 16:55:37--8:00 172.22.28.54 Action="accept" UUid="{0x0,0x0,0x0,0x0}" rule_guid="{700A45EF-633E-4BA5-BBBB-961D7664E72A}" hit="63" policy="fw1" first_hit_time="1425572108" last_hit_time="1425575690" log_id="10" product="VPN-1 & FireWall-1" product_family="Network"',
        # '<85>Mar 05 09:15:37+-8:00 172.22.28.54 Action="accept" UUid="{0x0,0x0,0x0,0x0}" rule_guid="{700A45EF-633E-4BA5-BBBB-961D7664E72A}" hit="63" policy="fw1" first_hit_time="1425572108" last_hit_time="1425575690" log_id="10" product="VPN-1 & FireWall-1" product_family="Network"',
        # '<85>Feb 28 09:30:10+00:00 192.168.133.152 Action="accept" UUid="{0x54ead64e,0x0,0x9885a8c0,0xc0000000}" rule="1" rule_uid="{37033D07-DF90-4AEB-B70D-A1D5E56BA70E}" service_id="ssh" src="192.168.133.1" dst="192.168.133.152" proto="6" product="VPN-1 & FireWall-1" service="22" s_port="60984" product_family="Network"',
        # '<85>Feb 28 15:38:10+02:00 192.168.133.152 Action="accept" UUid="{0x54ead64e,0x0,0x9885a8c0,0xc0000000}" rule="1" rule_uid="{37033D07-DF90-4AEB-B70D-A1D5E56BA70E}" service_id="ssh" src="192.168.133.1" dst="192.168.133.152" proto="6" product="VPN-1 & FireWall-1" service="22" s_port="60984" product_family="Network"',
        # '<85>Feb 28 19:38:03-02:00 192.168.133.152 Action="accept" UUid="{0x54ec76ff,0x0,0x9885a8c0,0xc0000000}" rule="1" rule_uid="{37033D07-DF90-4AEB-B70D-A1D5E56BA70E}" service_id="ssh_DFA" src="192.168.133.1" dst="192.168.133.152" proto="6" product="VPN-1 & FireWall-1" service="22" s_port="63316" product_family="Network"',
        # '<85>Feb 24 19:19:03+22:00 192.168.133.152 Action="accept" UUid="{0x54ec76ff,0x0,0x9885a8c0,0xc0000000}" rule="1" rule_uid="{37033D07-DF90-4AEB-B70D-A1D5E56BA70E}" service_id="ssh_DFA" src="192.168.133.1" dst="192.168.133.152" proto="6" product="VPN-1 & FireWall-1" service="22" s_port="63316" product_family="Network"',
        # '<85>Feb 25 01:19:03-04:00 192.168.133.152 Action="accept" UUid="{0x54ec76ff,0x0,0x9885a8c0,0xc0000000}" rule="1" rule_uid="{37033D07-DF90-4AEB-B70D-A1D5E56BA70E}" service_id="ssh_DFA" src="192.168.133.1" dst="192.168.133.152" proto="6" product="VPN-1 & FireWall-1" service="22" s_port="63316" product_family="Network"',
        # '<85>Feb 25 16:53:10+00:00 192.168.133.152 foo=bar zip="zap" test="some long test string"',  #test tokenizer:
    ]
    logging.getLogger().addHandler(logging.StreamHandler())
    logging.getLogger().setLevel(logging.DEBUG)

    print "Testing CheckPointSyslogMsg"
    for msg in syslog_msgs:
        print '-----------------------------'
        chkp_msg = CheckPointSyslogMsg(msg)
        print 'is_valid: %s' % chkp_msg.is_valid()
        print 'is_recent: %s' % chkp_msg.is_recent()
        print 'DECODED MSG:\n%s' % chkp_msg.decoded_msg()
        print 'timestamp: %s' % chkp_msg.timestamp
        print 'type: %s' % chkp_msg.type
        print 'FW action: %s' % chkp_msg.action
        print 'protocol: %s' % chkp_msg.protocol
        print 'app: %s' % chkp_msg.app
        print 'src_ip: %s' % chkp_msg.src_ip
        print 'dst_ip: %s' % chkp_msg.dst_ip
        print 'src_port: %s' % chkp_msg.src_port
        print 'dst_port: %s' % chkp_msg.dst_port
        print 'in_vlan: %s' % chkp_msg.in_vlan
        print 'in_intf: %s' % chkp_msg.in_intf
        print 'out_intf: %s' % chkp_msg.out_intf

if __name__ == "__main__":
    test()
