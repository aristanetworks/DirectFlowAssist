#!/usr/bin/env python2.7
#
# Copyright (c) 2014-2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = too-many-instance-attributes, line-too-long

''' Parses syslog messages from a Fortinet Fortigate Firewall
'''

import logging
import re
from directflow_assist.common import utils
from .SyslogMsg import SyslogMsg, scrub_app_name, tokenize_msg, dump_dict_sorted

TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M:%S'
VALID_INTERFACE_TYPES = ['port']


class FortigateSyslogMsg(SyslogMsg):
    ''' Parses syslog messages from a Fortinet Fortigate Firewall
    '''
    def __init__(self, raw_msg, *args, **kwargs):
        super(FortigateSyslogMsg, self).__init__(raw_msg, *args, **kwargs)

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
        self.src_ip = msg_dict.get('srcip', None)
        self.src_port = msg_dict.get('srcport', '0')
        self.in_intf = msg_dict.get('srcintf', None)
        self.dst_ip = msg_dict.get('dstip', None)
        self.dst_port = msg_dict.get('dstport', '0')
        self.out_intf = msg_dict.get('dstintf', None)

        protocol = msg_dict.get('proto', 'unknown')
        self.protocol = utils.IP_PROTOCOL.get(protocol, protocol)

        self.type = msg_dict.get('type', 'unknown')
        self.sub_type = msg_dict.get('subtype', 'unknown')

        # FortiGate syslog msg format changed between 5.0 and 5.2
        # new 'action' field was 'status' field
        if 'action' in msg_dict:
            self.action = msg_dict.get('action')
        elif 'status' in msg_dict:
            self.action = msg_dict.get('status')
        # self.rule_name=
        # self.log_fwd_name=
        self.timestamp = '%s %s' % (msg_dict.get('date', ''),
                                    msg_dict.get('time', ''))
        if 'app' in msg_dict:
            self.app = scrub_app_name(msg_dict['app'])
        elif 'attack' in msg_dict:
            self.app = scrub_app_name(msg_dict['attack'])
        elif 'attackname' in msg_dict:
            self.app = 'ATTACK:%s' % scrub_app_name(msg_dict['attackname'])
        elif 'service' in msg_dict:
            self.app = scrub_app_name(msg_dict['service'])
        else:
            self.app = 'unknown'
        return True

    def validate_intf(self, intf):
        ''' validate  Fortigate FW interface
         sample: srcintf="port11" dstintf="port12"
        '''
        if intf != '':
            regex = r'\s*([A-Za-z\-]*)(\d{1,3})'
            mobj = re.match(regex, intf)
            if mobj:
                intf_type = mobj.group(1)
                num = mobj.group(2)
                # sub = mobj.group(3)
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


def test():
    ''' test msg decoding
    '''
    # to run test:
    # PYTHONPATH=$PYTHONPATH::../persist_common:../persist_fnet
    # python FortigateSyslogMsg.py
    syslog_msgs = [
        '<13>date=2018-02-04 time=15:00:12 devname=FortiGate-500D devid=FGT5HD3914800308 logid=0000000015 type=traffic subtype=forward level=notice vd=FWTest srcip=172.22.28.190 srcport=53072 srcintf="port11" dstip=172.22.28.48 dstport=5989 dstintf="port12" poluuid=8bbd7af0-acbd-51e4-4cb0-a4a3a4e0a960 sessionid=28755 action=start policyid=1 dstcountry="Reserved" srccountry="Reserved" trandisp=noop service="tcp/5989" proto=6 duration=0 sentbyte=0 rcvdbyte=0',
        'date=2018-08-27 time=12:24:16 logid=0001000014 type=traffic subtype=local level=notice vd=root srcip=172.22.244.170 srcport=52175 srcintf="mgmt1" dstip=172.22.28.36 dstport=443 dstintf="root" sessionid=85814 status=close policyid=0 dstcountry="Reserved" srccountry="Reserved" trandisp=noop service=HTTPS proto=6 app="Web Management(HTTPS)" duration=29 sentbyte=21769 rcvdbyte=45494 sentpkt=63 rcvdpkt=55',
        'date=2018-08-27 time=10:11:46 logid=0001000014 type=traffic subtype=local level=notice vd=root srcip=172.22.28.177 srcport=138 srcintf="mgmt1" dstip=172.22.28.255 dstport=138 dstintf="root" sessionid=85486 status=deny policyid=0 dstcountry="Reserved" srccountry="Reserved" trandisp=noop service=138/udp proto=17 app=138/udp duration=0 sentbyte=0 rcvdbyte=0',
        '<13>date=2018-09-02 time=11:33:43 devname=FortiGate-500D devid=FGT5HD3914800308 logid=0000000015 type=traffic subtype=forward level=notice vd=root srcip=172.22.240.71 srcintf="port11" dstip=172.22.28.33 dstintf="port12" sessionid=860126 status=start policyid=1 dstcountry="Reserved" srccountry="Reserved" trandisp=noop proto=1 duration=0 sentbyte=0 rcvdbyte=0',
        '<9>date=2018-09-04 time=10:25:23 devname=FortiGate-500D devid=FGT5HD3914800308 logid=0420018433 type=utm subtype=ips eventtype=anomaly level=alert vd="FWTest" severity=critical srcip=172.22.240.129 dstip=172.22.28.32 srcintf="port11" policyid=N/A identidx=N/A sessionid=0 status=clear_session proto=1 service=icmp count=1 attackname="icmp_flood" icmpid=0x7966 icmptype=0x08 icmpcode=0x00 attackid=16777316 sensor="DoS-policy1" ref="http://www.fortinet.com/ids/VID16777316" msg="anomaly: icmp_flood, 4 > threshold 3"',
        '<13>date=2014-09-04 time=10:04:39 devname=FortiGate-500D devid=FGT5HD3914800308 logid=0000000013 type=traffic subtype=forward level=notice vd=FWTest srcip=172.22.240.129 srcintf="port11" dstip=172.22.28.32 dstintf="port12" sessionid=115384 status=deny policyid=2 dstcountry="Reserved" srccountry="Reserved" trandisp=noop service=PING proto=1 duration=0 sentbyte=0 rcvdbyte=0',
    ]
    logging.getLogger().addHandler(logging.StreamHandler())
    logging.getLogger().setLevel(logging.DEBUG)

    print "Testing FortigateSyslogMsg"
    for msg in syslog_msgs:
        print '---------------------'
        fsm = FortigateSyslogMsg(msg)
        print 'is_valid: %s' % fsm.is_valid()
        print 'DECODED MSG:\n%s' % fsm.decoded_msg()
        print 'FW action: %s' % fsm.action
        print 'Protocol: %s' % fsm.protocol
        print 'app: %s' % fsm.app
        print 'src_ip: %s' % fsm.src_ip
        print 'dst_ip: %s' % fsm.dst_ip
        print 'src_port: %s' % fsm.src_port
        print 'dst_port: %s' % fsm.dst_port
        print 'in_intf: %s' % fsm.in_intf
        print 'out_intf: %s' % fsm.out_intf
        print 'check timestamp: %s, is_recent: %s' % (fsm.timestamp,
                                                      fsm.is_recent())

if __name__ == "__main__":
    test()
