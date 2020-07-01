#!/usr/bin/env python2.7
#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = too-many-instance-attributes, line-too-long

''' Parses syslog messages from a vArmour EP (Enforcement Point)

Samples from vArmour:
May 20 12:58:07 000 vArmour va_syslog: [Chassis(vArmour):Device(4):VA_APP_ANET_RTLOG] sip=44.1.1.54 sport=47298 dip=44.1.1.55 dport=22 proto=6 c2s-pkts=10 s2c-pkts=11 sess-close-reason=policy-permit c2s-bytes=1849 s2c-bytes=1809 sintf=xe-4/0/4 dintf=xe-4/0/5
May 20 13:03:41 000 vArmour va_syslog: [Chassis(vArmour):Device(4):VA_APP_ANET_RTLOG] sip=44.1.1.55 sport=35813 dip=44.1.1.54 dport=23 proto=6 c2s-pkts=0 s2c-pkts=0 sess-close-reason=policy-deny c2s-bytes=0 s2c-bytes=0 sintf=xe-4/0/5 dintf=xe-4/0/4

'''

import logging
import time
import re
from . import util
from directflow_assist.common import utils
from .SyslogMsg import SyslogMsg, tokenize_msg, dump_dict_sorted

TIMESTAMP_FORMAT = '%Y %b %d %H:%M:%S'
VALID_INTERFACE_TYPES = ['xe']
VARMOUR = 'vArmour'


class VarmourSyslogMsg(SyslogMsg):
    ''' Parses syslog messages from a vArmour EP (Enforcement Point)
    '''
    def __init__(self, raw_msg, *args, **kwargs):
        super(VarmourSyslogMsg, self).__init__(raw_msg, *args, **kwargs)

    def get_timestamp_format(self):
        return TIMESTAMP_FORMAT

    def preprocess_raw_msg(self):
        ''' preprocess
        '''
        msg = self.raw_msg.strip()  # remove leading and trailing whitespace
        # remove leading <NN> prefix if present
        mobj = re.match(r'(<\d{1,6}>)?(.*)', msg)
        # logging.debug('preprocess g1: %s, g2: %s',
        #               mobj.group(1), mobj.group(2))
        return mobj.group(2)

    def parse_msg(self):
        ''' parse
        '''
        msg_string = self.preprocess_raw_msg()
        msg_dict = {}
        for token in tokenize_msg(msg_string):
            key, value = token.split('=')
            msg_dict[key] = value.strip('"')

        self.msg_dict = msg_dict
        self.src_ip = msg_dict.get('sip', None)
        self.src_port = msg_dict.get('sport', '0')
        self.in_intf = msg_dict.get('sintf', None)
        self.dst_ip = msg_dict.get('dip', None)
        self.dst_port = msg_dict.get('dport', '0')
        self.out_intf = msg_dict.get('dintf', None)
        self.timestamp = extract_timestamp(msg_string)
        self.action = msg_dict.get('sess-close-reason', '?')
        self.type = VARMOUR if VARMOUR in msg_string else 'unknown'
        protocol = msg_dict.get('proto', 'unknown')
        self.protocol = utils.IP_PROTOCOL.get(protocol, protocol)
        self.app = utils.determine_app(protocol, self.dst_port)
        return True

    def validate_intf(self, intf):
        ''' validate  vArmour EP interface
            from vArmour: "The exact interface field value format will be:
             xe-<node_id>/0/<port_id>.
             For example, xe-4/0/5, where node_id is 4 and port id is 5."
        '''
        if intf != '':
            regex = r'\s*(xe)-.+/.+/(\d{1,4})'
            mobj = re.match(regex, intf)
            if mobj:
                intf_type = mobj.group(1)
                num = mobj.group(2)
                logging.debug('validate_intf [%s] type [%s] num [%s]',
                              intf, intf_type, num)
                if intf_type in VALID_INTERFACE_TYPES:
                    return
        logging.warning('SyslogMsg: invalid interface [%s] ', intf)
        self.valid_msg = False

    def decoded_msg(self):
        ''' return parsed msg
        '''
        return dump_dict_sorted(self.msg_dict)


def extract_timestamp(msg):
    ''' extract timestamp and validate fields
        sample: May 18 14:09:19 000 vArmour va_syslog:
    '''
    mobj = re.match(r'\s*([A-Za-z]{3,4}) (\d{1,2}) '
                    r'(\d{1,2}:\d{1,2}:\d{1,2}).*', msg)
    if not mobj:
        return None
    (month, date, hms_time) = mobj.groups()
    this_year = time.gmtime()[0]
    timestamp = '%s %s %s %s' % (this_year, month, date, hms_time)
    # print timestamp
    return timestamp


# -----------------------------------------------------------------------------
def test():
    ''' test msg decoding
    '''
    # to run test:
    # PYTHONPATH=$PYTHONPATH::../persist_common:../persist_varmour
    # python VarmourSyslogMsg.py
    # syslog_msgs = util.load_from_file('../persist_varmour/syslog_samples.dat')
    syslog_msgs = util.load_from_file('../tools/data/varmour_syslogs.dat')

    logging.getLogger().addHandler(logging.StreamHandler())
    logging.getLogger().setLevel(logging.DEBUG)

    print "Testing VarmourSyslogMsg"
    for msg in syslog_msgs:
        print '---------------------'
        print 'raw msg=%s' % msg
        smsg = VarmourSyslogMsg(msg)
        print 'is_valid: %s' % smsg.is_valid()
        print 'DECODED MSG:\n%s' % smsg.decoded_msg()
        print 'type: %s' % smsg.type
        print 'action: %s' % smsg.action
        print 'protocol: %s' % smsg.protocol
        print 'app: %s' % smsg.app
        print 'app_short: %s' % smsg.app_short
        print 'src_ip: %s' % smsg.src_ip
        print 'dst_ip: %s' % smsg.dst_ip
        print 'src_port: %s' % smsg.src_port
        print 'dst_port: %s' % smsg.dst_port
        print 'in_intf: %s' % smsg.in_intf
        print 'out_intf: %s' % smsg.out_intf
        print 'check timestamp: %s, is_recent: %s' % (smsg.timestamp,
                                                      smsg.is_recent())

if __name__ == "__main__":
    test()
