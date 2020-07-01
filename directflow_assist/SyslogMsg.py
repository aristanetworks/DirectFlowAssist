#!/usr/bin/env python2.7
#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = wildcard-import, unused-wildcard-import, line-too-long
# pylint: disable = too-many-instance-attributes

''' Base syslog message
'''

import logging
import time
import config
from directflow_assist.common import utils


class SyslogMsg(object):
    ''' Base syslog message
    '''
    def __init__(self, raw_msg):
        self.raw_msg = raw_msg
        self.msg = None
        self.msg_dict = {}
        self.type = None
        self.sub_type = None
        self.action = None
        self.rule_name = None
        self.log_fwd_name = None
        self.protocol = None
        self.app = None
        self.app_short = None
        self.src_ip = None
        self.src_port = None
        self.dst_ip = None
        self.dst_port = None
        self.in_intf = None
        self.in_vlan = None          # aka. subinterface
        self.out_intf = None
        self.out_vlan = None         # aka. subinterface
        self.msg_labels = None
        self.timestamp = 0
        self.msg_age_seconds = 0
        self.valid_msg = False
        self.process()

    def process(self):
        ''' process firewall syslog message.
        '''
        parse_success = self.parse_msg()
        if parse_success:
            self.app_short = self.app[:config.APP_NAME_MAX_CHARS]
            self.validate_msg()

    def is_valid(self):
        ''' confirm msg is_valid before accessing any other object attributes
        '''
        return self.valid_msg

    def validate_msg(self):
        ''' validate
        '''
        if not self.is_recent():
            logging.info('old msg: timestamp %s is older than '
                         'MAX_SYSLOG_MSG_AGE: %sm', self.timestamp,
                         config.MAX_SYSLOG_MSG_AGE)
            return
        self.valid_msg = True
        # self.validate_ip_addr(self.src_ip, 'Source')
        # self.validate_ip_addr(self.dst_ip, 'Dest')
        # self.validate_l4_port(self.src_port, 'Source', optional=True)
        # self.validate_l4_port(self.dst_port, 'Dest', optional=True)
        # self.validate_protocol(self.protocol)
        if self.in_intf:
            self.validate_intf(self.in_intf)
        if self.out_intf:
            self.validate_intf(self.out_intf)

    def is_recent(self):
        ''' check age
        '''
        # logging.debug('msg timestamp: %s', self.timestamp )
        if not self.timestamp:
            return False
        timestamp_format = self.get_timestamp_format()
        msg_ts_secs = int(time.mktime(time.strptime(self.timestamp,
                                                    timestamp_format)))
        now_secs = int(time.time())
        self.msg_age_seconds = now_secs - msg_ts_secs
        max_age_secs = config.MAX_SYSLOG_MSG_AGE * 60
        logging.debug('msg timestamp: %s, msg_age_seconds: %s, max_age_secs: '
                      '%s', self.timestamp, self.msg_age_seconds, max_age_secs)
        if self.msg_age_seconds <= max_age_secs:
            return True
        else:
            return False

    def validate_ip_addr(self, ip_addr, label):
        ''' validate
        '''
        if not utils.is_valid_ip_addr(ip_addr):
            logging.warning('SyslogMsg: invalid %s IP address: %s', label,
                            ip_addr)
            self.valid_msg = False

    def validate_l4_port(self, port, label, optional=False):
        ''' validate
        '''
        if not port or int(port) > 65535:
            logging.warning('FortigateSyslogMsg: %s L4 port: %s',
                            label, port)
            if not optional:
                self.valid_msg = False

    def validate_protocol(self, proto):
        ''' validate
        '''
        if not proto or proto.lower() not in ['tcp', 'udp', 'icmp']:
            logging.warning('SyslogMsg: invalid protocol: %s', proto)
            self.valid_msg = False

    def validate_intf(self, intf):
        ''' must be implemented in subclass
        '''
        pass

    def parse_msg(self):
        ''' must be implemented in subclass
        '''
        pass

    def get_timestamp_format(self):
        ''' must be implemented in subclass
        '''
        pass


def tokenize_msg(msg_string):
    ''' can't just use split since some value fields have spaces within
        quotes, e.g. dstcountry="United States" srccountry="Reserved"
        srcip=172.22.244.170
        return [ m.split('=') for m in self.raw_msg.split() ]
     '''
    tokens = []
    first_pass = [m for m in msg_string.split()]
    within_quotes = False
    for item in first_pass:
        # logging.debug('tokenize_msg item: %s', item)
        if '=' in item:
            tokens.append(item)
            if '="' in item and not item.endswith('"'):
                within_quotes = True
        elif within_quotes:
            # merge quoted string w/ last token
            tokens[-1] = tokens[-1] + " " + item
            if item.endswith('"'):
                within_quotes = False  # reset
    # logging.debug('tokenized msg: %s', tokens)
    return tokens


def scrub_app_name(name):
    ''' scrub for use in EOS flow name
    '''
    delete_chars = r'~`!@#$%^&*()+={}[];|\/?><,.'
    name = name.translate(None, delete_chars)
    name = name.replace(' ', '_')
    name = name.replace('/', '_')
    return name


def dump_dict_sorted(adict):
    ''' util
    '''
    out = ''
    for key in sorted(adict.keys()):
        value = adict[key]
        if value:
            out += '%s =  %s\n' % (key.ljust(12), value)
    return out

# if __name__ == "__main__":
#     print 'SyslogMsg unittest'
#     sm = SyslogMsg('')
#     print 'SyslogMsg is_valid: %s' % sm.is_valid()
