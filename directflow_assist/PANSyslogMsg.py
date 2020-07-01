#!/usr/bin/env python2.7
#
# Copyright (c) 2014-2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = wildcard-import, unused-wildcard-import, line-too-long
# pylint: disable = too-many-instance-attributes

''' Parses syslog messages from Palo Alto Networks Firewalls
'''

import logging
import re
import config
from .SyslogMsg import SyslogMsg, scrub_app_name

TIMESTAMP_FORMAT = '%Y/%m/%d %H:%M:%S'

VALID_INTERFACE_TYPES = ['ethernet', 'ae']    # ae = aggregate ethernet chan.
PAN_SYSLOG_MSG_TYPE_IDX = 3
PAN_SYSLOG_MSG_SUBTYPE_IDX = 4


class PANSyslogMsg(SyslogMsg):
    ''' Parses syslog messages from Palo Alto Networks Firewalls
    '''

    def __init__(self, raw_msg, *args, **kwargs):
        super(PANSyslogMsg, self).__init__(raw_msg, *args, **kwargs)

    def get_timestamp_format(self):
        return TIMESTAMP_FORMAT

    def parse_msg(self):
        ''' parse
        '''
        self.preprocess_raw_msg()
        if not self.msg_labels:
            return False
        self.src_port = self.msg[self.msg_labels.index('Source Port')]
        self.dst_port = self.msg[self.msg_labels.index('Destination Port')]
        self.protocol = self.msg[self.msg_labels.index('IP Protocol')]
        self.src_ip = self.msg[self.msg_labels.index('Source address')]
        self.dst_ip = self.msg[self.msg_labels.index('Destination address')]
        self.rule_name = self.msg[self.msg_labels.index('Rule')]
        self.log_fwd_name = self.msg[self.msg_labels.index('Log Action')]

        if self.type == 'TRAFFIC':
            inbound_intf = self.msg[self.msg_labels.index('Inbound Interface')]
            outbound_intf = \
                self.msg[self.msg_labels.index('Outbound Interface')]
            self.in_intf, self.in_vlan = parse_intf_and_vlan(inbound_intf)
            self.out_intf, self.out_vlan = parse_intf_and_vlan(outbound_intf)
            app_name = self.msg[self.msg_labels.index('Application')]
        elif self.type == 'THREAT':
            app_name = self.msg[self.msg_labels.index('Threat/Content Name')]
        else:
            logging.warning('Unknown syslog msg type')
            return False

        self.app = scrub_app_name(app_name)
        # logging.debug('FW policy name: %s, log_fwd_name: %s', self.rule_name,
        #             self.log_fwd_name)
        self.load_msg_dict()
        return True

    def preprocess_raw_msg(self):
        ''' Determine if msg is a Palo Alto Networks Firewall syslog message.
            For more on PAN syslog message types and formats see:
            https://live.paloaltonetworks.com/docs/DOC-2021
        '''
        # convert CSV msg to a list
        self.msg = self.raw_msg.split(',')
        if len(self.msg) > max(PAN_SYSLOG_MSG_TYPE_IDX,
                               PAN_SYSLOG_MSG_SUBTYPE_IDX):
            self.type = self.msg[PAN_SYSLOG_MSG_TYPE_IDX]
            self.set_msg_field_labels()
            logging.debug('syslog msg: type [%s] subtype [%s] action [%s]',
                          self.type, self.sub_type, self.action)

    def load_msg_dict(self):
        ''' load self.msg_dict from labels and syslog msg field values
        '''
        for idx, label in enumerate(self.msg_labels):
            self.msg_dict[label] = self.msg[idx]

    def set_msg_field_labels(self):
        ''' map csv to named fields
        '''
        if self.type not in config.PAN_SYSLOG_FIELD_LABELS.keys():
            logging.error('No field labels found for PAN syslog msg type: %s',
                          self.type)
        else:
            labels = config.PAN_SYSLOG_FIELD_LABELS[self.type]
            # PAN may add fields to end of msgs in future releases
            if len(self.msg) < len(labels):
                logging.warning('syslog msg has only %d fields, %d required to'
                                ' decode, check PAN-OS min. supported version',
                                len(self.msg), len(labels))
                return
            self.msg_labels = labels
            self.sub_type = self.msg[PAN_SYSLOG_MSG_SUBTYPE_IDX]
            self.action = self.msg[self.msg_labels.index('Action')]
            self.timestamp = self.msg[self.msg_labels.index('Receive Time')]
            # logging.debug('field labels assigned for PAN syslog msg type: %s',
            #               self.type)

    def validate_intf(self, intf):
        ''' validate PAN FW interface
        '''
        if intf:
            regex = r'^\s*([A-Za-z\-]+).*'
            mobj = re.match(regex, intf)
            if mobj:
                intf_type = mobj.group(1)
                if intf_type in VALID_INTERFACE_TYPES:
                    return
        logging.warning('PANSyslogMsg: invalid interface [%s] ', intf)
        self.valid_msg = False

    def validate_protocol(self, proto):
        ''' validate protocol
            override to add support for hopopt
        '''
        if not proto or proto.lower() not in ['tcp', 'udp', 'icmp', 'hopopt']:
            logging.warning('SyslogMsg: invalid protocol: %s', proto)
            self.valid_msg = False

    def decoded_msg(self):
        ''' returns msg with field names and values
        '''
        out = ''
        for j, label in enumerate(self.msg_labels):
            value = self.msg[j]
            if value == '':   # filter out fields with no value
                continue
            out += '%s = %s\n' % (label, value)
        if self.in_vlan:
            out += '*in_vlan = %s\n' % self.in_vlan
            out += '*in_intf = %s\n' % self.in_intf
        if self.out_vlan:
            out += '*out_vlan = %s\n' % self.out_vlan
            out += '*out_intf = %s\n' % self.out_intf
        if self.in_vlan and self.out_vlan and (self.in_vlan != self.out_vlan):
            logging.warning('ingress and egress VLANs are not the same')
        return out


def parse_intf_and_vlan(intf):
    ''' parse interface and if present subinterface.  Subinterface is
        a vlan, valid PAN interface formats:
          ethernet1/5
          ethernet1/5.10      10 = subinterface = vlan
          ae3                 aggregate ethernet interface (aka. port channel)
    '''
    if not intf:
        return None, None
    regex = r'\s*([A-Za-z\-]+\d{1,3}(/\d{1,3})?)\.?(\d{1,4})?$'
    mobj = re.match(regex, intf)
    if mobj:
        intf, vlan = mobj.group(1, 3)
        # print 'intf: %s, vlan: %s' % (intf,vlan)
        return intf, vlan
    else:
        logging.warning('PANSyslogMsg: unable to parse interface: %s', intf)
        return None, None


def compare_msg_field_names():
    ''' debug helper
    '''
    traffic_msg_fields = config.PAN_SYSLOG_FIELD_LABELS['TRAFFIC']
    threat_msg_fields = config.PAN_SYSLOG_FIELD_LABELS['THREAT']
    print 'len traffic_msg_fields=%d \nlen threat_msg_fields=%d' \
        % (len(traffic_msg_fields), len(threat_msg_fields))
    for j in range(min(len(traffic_msg_fields), len(threat_msg_fields))):
        traffic = traffic_msg_fields[j]
        threat = threat_msg_fields[j]
        print '%s  %s  %s' % ((traffic == threat), traffic.ljust(20), threat,)


def test():
    '''
     to run test:
     PYTHONPATH=$PYTHONPATH::../persist_common:../persist_pan
     python PANSyslogMsg.py
     real syslog msgs strings as received (w/ modified timestamps)
    '''
    print "Testing PANSyslogMsg"
    syslog_msgs = [
        'Feb 12 15:10:06 PA-5050 1,2018/02/12 15:10:06,0009C103236,THREAT,virus,1,2015/02/12 15:10:06,188.40.238.250,10.128.50.2,0.0.0.0,0.0.0.0,rule2,,,web-browsing,vsys1,vwire1-untrust,vwire1-trust,ethernet1/2,ethernet1/1,Threat log fws to Arista,2015/02/12 15:10:06,33606445,1,80,45608,0,0,0x0,tcp,deny,"eicar.com",Eicar Test File(100000),any,medium,server-to-client,222,0x0,DE,10.0.0.0-10.255.255.255,0,,0,,',
        'Feb 12 16:04:56 PA-5050 1,2018/02/12 16:04:56,0009C103236,THREAT,spyware,1,2015/02/12 16:04:56,112.78.22.47,192.168.204.150,0.0.0.0,0.0.0.0,Tap,,,unknown-tcp,vsys1,Tap,Tap,ethernet1/6,ethernet1/6,Threat log fws to Arista,2015/02/12 16:04:56,33606610,1,80,1040,0,0,0x0,tcp,reset-both,"",PoisonIvy.RAT Command and Control Traffic(13172),any,critical,server-to-client,223,0x0,TW,192.168.0.0-192.168.255.255,0,,0,, ',
        'Feb 13 11:42:08 PA-5050 1,2019/02/13 11:42:08,0009C103236,THREAT,spyware,1,2015/02/13 11:42:08,10.128.50.2,8.8.8.8,0.0.0.0,0.0.0.0,rule2,,,dns,vsys1,vwire1-trust,vwire1-untrust,ethernet1/1,ethernet1/2,Threat log fws to Arista,2015/02/13 11:42:08,33610810,2,9006,53,0,0,0x0,udp,drop-all-packets,"",Suspicious DNS Query (generic:hashimshafiq.no-ip.biz)(4100111),any,medium,client-to-server,265,0x0,10.0.0.0-10.255.255.255,US,0,,0,, ',
        'Feb 12 16:25:33 PA-5050 1,2018/02/12 16:25:33,0009C103236,THREAT,vulnerability,1,2015/02/12 16:25:33,192.168.204.150,10.246.50.7,0.0.0.0,0.0.0.0,Tap,,,ssl,vsys1,Tap,Tap,ethernet1/6,ethernet1/6,Threat log fws to Arista,2015/02/12 16:25:33,33606693,1,54848,443,0,0,0x0,tcp,reset-server,"",OpenSSL TLS Heartbeat Information Disclosure Vulnerability - Heartbleed(36416),any,critical,client-to-server,226,0x0,192.168.0.0-192.168.255.255,10.0.0.0-10.255.255.255,0,,0,, ',
        'Feb 12 13:17:17 PA-5050 1,2018/02/12 13:17:16,0009C103236,THREAT,wildfire,0,2015/02/12 13:17:16,62.149.132.147,192.168.204.150,0.0.0.0,0.0.0.0,Tap,,,web-browsing,vsys1,Tap,Tap,ethernet1/6,ethernet1/6,Threat log fws to Arista,2015/02/12 13:17:16,33606002,1,80,50080,0,0,0x0,tcp,alert,"document22092014_73327_pdf.exe",428148050(428148050),malicious,medium,server-to-client,190,0x0,IT,192.168.0.0-192.168.255.255,0,,0,8040c1cee63db55b348dea8f07ad42d1c78f9ed2c4ff90a9f9accffa7aba186f,ca-s1.wildfire.paloaltonetworks.com',
        'Feb 18 13:59:26 PA-5050 1,2019/02/18 13:59:25,0009C103236,THREAT,flood,1,2015/02/18 13:59:25,10.128.50.2,0.0.0.0,0.0.0.0,0.0.0.0,rule1,,,not-applicable,vsys1,vwire1-trust,vwire1-untrust,,,Log fwd to Arista,2015/02/18 13:59:25,0,1,0,0,0,0,0x0,udp,drop,"",UDP Flood(8502),any,critical,client-to-server,318,0x0,10.0.0.0-10.255.255.255,0.0.0.0-0.255.255.255,0,,0,, ',
        # "<10>Mar 15 12:33:53 PA-5060-1 1,2018/03/15 12:33:53,001901000869,THREAT,flood,1,2015/03/15 12:33:53,62.119.40.174,194.218.146.221,0.0.0.0,0.0.0.0,Test DOS policy,,,not-applicable,vsys1,SPSEBORTelia01,SPSEBORDMZ41,,,Arista boost,2015/03/15 12:33:53,0,1009,0,0,0,0,0x0,tcp,drop,"",TCP Flood(8501),any,critical,client-to-server,59070,0x0,SE,SE,0,,0,,,0,,,,,,,,0",
        # "<10>Mar 26 18:32:28 1,2015/03/26 18:32:28,001801004217,THREAT,flood,1,2015/03/26 18:32:22,172.22.28.77,172.22.28.28,0.0.0.0,0.0.0.0,DEMO_Dos_Attack,,,not-applicable,vsys1,untrust2,trust2,,,Demo_DirectFlow_Assist,2015/03/26 18:32:28,0,6,0,0,0,0,0x0,icmp,drop,"",ICMP Flood(8503),any,critical,client-to-server,105,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,",
        # "<14>Jul  1 16:50:16 PA-5050 1,2018/12/5 13:15:16,0009C101677,TRAFFIC,start,1,2018/12/5 16:50:16,172.22.243.135,172.22.28.33,0.0.0.0,0.0.0.0,Dev_Backup_flow_4m,,,ping,vsys1,untrust,trust,ethernet1/1,ethernet1/2,Dev_DirectFlow_Assist,2018/12/5 16:50:16,198442,59,0,0,0,0,0x0,icmp,allow,6018,6018,0,59,2018/12/5 16:50:10,0,any,0,1549277,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,59,0 ",
        # "<10>Jul  1 16:54:37 PA-5050 1,2018/12/5 13:15:37,0009C101677,THREAT,flood,1,2018/12/5 16:54:37,172.22.243.135,172.22.28.32,0.0.0.0,0.0.0.0,Dev_DoS_Attack_2m,,,not-applicable,vsys1,untrust,trust,,,Dev_DirectFlow_Assist,2018/12/5 16:54:37,0,1,0,0,0,0,0x0,icmp,allow,"",ICMP Flood(8503),any,critical,client-to-server,2321,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,,0,,",
        # "<10>Jul  1 16:54:38 PA-5050 1,2018/12/5 13:15:38,0009C101677,THREAT,flood,1,2018/12/5 16:54:38,172.22.243.135,172.22.28.32,0.0.0.0,0.0.0.0,Dev_DoS_Attack_2m,,,not-applicable,vsys1,untrust,trust,,,Dev_DirectFlow_Assist,2018/12/5 16:54:38,0,59,0,0,0,0,0x0,icmp,drop,"",ICMP Flood(8503),any,critical,client-to-server,2322,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,,0,,",
        # "<10>Jul  1 16:57:58 PA-5050 1,2018/12/5 13:15:58,0009C101677,THREAT,flood,1,2018/12/5 16:57:58,172.22.243.135,172.22.28.32,0.0.0.0,0.0.0.0,Dev_DoS_Attack_2m,,,not-applicable,vsys1,untrust,trust,,,Dev_DirectFlow_Assist,2018/12/5 16:57:58,0,2,0,0,0,0,0x0,icmp,allow,"",ICMP Flood(8503),any,critical,client-to-server,2324,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,,0,, ",
        # "<10>Jul  1 16:57:58 PA-5050 1,2018/12/5 13:15:58,0009C101677,THREAT,flood,1,2018/12/5 16:57:58,172.22.243.135,172.22.28.32,0.0.0.0,0.0.0.0,Dev_DoS_Attack_2m,,,not-applicable,vsys1,untrust,trust,,,Dev_DirectFlow_Assist,2018/12/5 16:57:58,0,1,0,0,0,0,0x0,icmp,random-drop,"",ICMP Flood(8503),any,critical,client-to-server,2325,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,,0,, ",
        # "<14>Jul  1 17:00:00 PA-5050 1,2018/12/5 13:15:00,0009C101677,TRAFFIC,start,1,2018/12/5 17:00:00,172.22.135,172.300.28.33,0.0.0.0,0.0.0.0,Dev_Backup_flow_4m,,,ping,vsys1,untrust,trust,ethernet1/1.10,ethernet1/2.10,Dev_DirectFlow_Assist,2018/12/5 17:00:00,198694,54,0,0,0,0,0x0,icmp,allow,5508,5508,0,54,2018/12/5 16:59:54,0,any,0,1549353,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,54,0",
        # "<14>Jul  2 10:57:32 PA-5050 1,2018/12/5 13:15:32,0009C101677,TRAFFIC,start,1,2018/07/02 10:57:32,172.22.243.135,172.22.28.33,0.0.0.0,0.0.0.0,Dev_Backup_flow_4m,,,ping,vsys1,untrust,trust,ethernet1/1,ethernet1/2,Dev_DirectFlow_Assist,2018/07/02 10:57:32,208624,2,0,0,0,0,0x0,icmp,allow,204,204,0,2,2018/07/02 10:57:26,0,any,0,1557781,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,2,0 ",
        # "<14>Jul  2 10:57:32 PA-5050 1,2018/12/5 13:15:32,0009C101677,TRAFFIC,start,1,2018/07/02 10:57:32,172.22.243.135,172.22.28.33,0.0.0.0,0.0.0.0,Dev_Backup_flow_4m,,,ping,vsys1,untrust,trust,ethernet1/1.10,ethernet1/2.10,Dev_DirectFlow_Assist,2018/07/02 10:57:32,208624,2,0,0,0,0,0x0,icmp,allow,204,204,0,2,2018/07/02 10:57:26,0,any,0,1557781,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,2,0 ",
        # "<14>Jul  2 10:57:32 PA-5050 1,2018/12/5 13:15:32,0009C101677,TRAFFIC,start,1,2018/07/02 10:57:32,172.22.243.135,172.22.28.33,0.0.0.0,0.0.0.0,Dev_Backup_flow_4m,,,ping,vsys1,untrust,trust,ae1,ae2,Dev_DirectFlow_Assist,2018/07/02 10:57:32,208624,2,0,0,0,0,0x0,icmp,allow,204,204,0,2,2018/07/02 10:57:26,0,any,0,1557781,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,2,0 ",
        # "<14>Jul  2 10:57:32 PA-5050 1,2018/12/5 13:15:32,0009C101677,DUMMY,start,1,2018/07/02 10:57:32,172.22.243.135,172.22.28.33,0.0.0.0,0.0.0.0,Dev_Backup_flow_4m,,,ping,vsys1,untrust,trust,ethernet1/1.10,ethernet1/2.10,Dev_DirectFlow_Assist,2018/07/02 10:57:32,208624,2,0,0,0,0,0x0,icmp,allow,204,204,0,2,2018/07/02 10:57:26,0,any,0,1557781,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,2,0 ",
        # "<14>Jul  2 10:57:32 PA-5050 1,2018/12/5 13:15:32,0009C101677,DUMMY,start,1,2018/07/02 10:57:32,172.22.243.135,172.22.28.33,0.0.0.0,0.0.0.0,Dev_Backup_flow_4m,,,ping,vsys1,untrust,trust,ae1,ae2,Dev_DirectFlow_Assist,2018/07/02 10:57:32,208624,2,0,0,0,0,0x0,icmp,allow,204,204,0,2,2018/07/02 10:57:26,0,any,0,1557781,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,2,0 ",
        # <10>Jul  1 16:57:58 PA-5050 1,2018/12/5 13:15:58,0009C101677,BAD_MSG,flood,,,1,2,3",
        # " <14>Jul 24 15:29:32 PA-5050  : 1,2018/07/24 15:29:31,0009C101677,TRAFFIC,start,1,2018/07/24 15:29:31,172.22.28.190,172.22.28.31,0.0.0.0,0.0.0.0,Dev_Redirect,,,ssl,vsys1,tap_untrust,tap_untrust,ethernet1/5,ethernet1/5,Dev_DirectFlow_Assist,2018/07/24 15:29:31,33834737,1,58178,5989,0,0,0x0,tcp,allow,418,418,0,3,2018/07/24 15:29:31,0,any,0,1746391,0x0,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,3,0",
    ]
    logging.getLogger().addHandler(logging.StreamHandler())
    logging.getLogger().setLevel(logging.DEBUG)

    for msg in syslog_msgs:
        print '---------------------'
        psm = PANSyslogMsg(msg)
        print 'is_valid: %s' % psm.is_valid()
        if psm.is_valid():
            print 'DECODED MSG:\n%s' % psm.decoded_msg()
