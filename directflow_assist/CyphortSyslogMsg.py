#!/usr/bin/env python2.7
#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = too-many-instance-attributes, line-too-long

''' Parses syslog messages from a Cyphort Malware Defense System
'''

import logging
import re
import config
from .SyslogMsg import SyslogMsg, tokenize_msg, dump_dict_sorted

TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M:%S'


class CyphortSyslogMsg(SyslogMsg):
    ''' Parses syslog messages from a Cyphort Malware Defense System
    '''
    def __init__(self, raw_msg, *args, **kwargs):
        super(CyphortSyslogMsg, self).__init__(raw_msg, *args, **kwargs)
        self.preamble = None

    def get_timestamp_format(self):
        return TIMESTAMP_FORMAT

    def preprocess_raw_msg(self):
        ''' preprocess
        '''
        msg = self.raw_msg.strip()  # remove leading and trailing whitespace
        # remove leading <NN> prefix if present
        mobj = re.match(r'(<\d{1,6}>)?(.*)\|(.*)', msg)
        # logging.debug('preprocess preamble: %s \nrest-of-msg: %s',
        #              mobj.group(2), mobj.group(3))
        self.preamble = mobj.group(2)
        return mobj.group(3)

    def parse_msg(self):
        ''' parse
        '''
        msg_string = self.preprocess_raw_msg()
        msg_dict = {}
        for token in tokenize_msg(msg_string):
            key, value = token.split('=')
            msg_dict[key] = value.strip('"')

        self.msg_dict = msg_dict
        self.src_ip = msg_dict.get('src', None)
        self.dst_ip = msg_dict.get('dst', None)

        mobj = re.search(r'(?:.*\|){4}(.*)\|(.*)\|', self.preamble)
        if mobj:
            self.type = mobj.group(1)
            self.sub_type = mobj.group(2)
            self.msg_dict['type'] = self.type
            self.msg_dict['subtype'] = self.sub_type

        # extract timestamp, sample: 2015-02-23 17:36:39
        mobj = re.search(r'(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)',
                         self.preamble)
        if mobj:
            self.timestamp = mobj.group(1)
        self.set_app()
        return True

    def set_app(self):
        ''' determine app
        '''
        if not self.type:
            return

        if self.type and not self.sub_type:
            self.app = self.type
        # special handling for demo so short app name can include 'CreditCard'
        elif 'CreditCard_Rule' in self.sub_type:
            self.app = '%s:%s' % (self.type, 'CreditCard_Rule')
        else:
            self.app = '%s:%s' % (self.type, self.sub_type)

    def validate_msg(self):
        ''' validate; override since many fields not applicable for Cyphort
            drop only use case
        '''
        if not self.is_recent():
            logging.info('old msg: timestamp %s is older than '
                         'MAX_SYSLOG_MSG_AGE: %sm', self.timestamp,
                         config.MAX_SYSLOG_MSG_AGE)
            return
        self.valid_msg = True
        self.validate_ip_addr(self.src_ip, 'Source')
        # self.validate_ip_addr(self.dst_ip, 'Dest')

    def decoded_msg(self):
        ''' return parsed msg
        '''
        return dump_dict_sorted(self.msg_dict)


def test():
    ''' test msg decoding
    '''
    # to run test:
    # PYTHONPATH=$PYTHONPATH::../persist_common:../persist_cyphort
    # python CyphortSyslogMsg.py
    syslog_msgs = [
        '2019-02-23 17:36:39.841+00 tap0.test.cyphort.com CEF:0|Cyphort|Cortex|3.2.1.16|cnc|TROJAN_Zemot.CY|7|externalId=995 eventId=123 lastActivityTime=2015-02-23 17:36:39.841+00 src=50.154.149.189 dst=192.168.1.10 malwareSeverity=0.5 malwareCategory=Trojan_DataTheft cncServers=50.154.149.189',
        '2019-04-10 13:20:00.841+00 tap0.test.cyphort.com CEF:0|Cyphort|Cortex|3.2.1.16|datatheft|2ND_ORDER_DLP_CUSTOMIZED : CreditCard_Rule|7|externalId=995 eventId=123 lastActivityTime=2015-02-23 17:36:39.841+00 src=50.154.149.189 dst=192.168.1.10 description=2ND_ORDER_DLP_CUSTOMIZED : CreditCard_Rule port=80 protocol=HTTP startTime=2015-02-23 17:36:39.841+00',
        '2019-02-23 17:36:39.841+00 tap0.test.cyphort.com CEF:0|Cyphort|Cortex|3.2.1.16|email|TROJAN_Zemot.CY|7|externalId=995 eventId=123 lastActivityTime=2015-02-23 17:36:39.841+00 src=50.154.149.189 dst=192.168.1.10 fileHash=d93216633bf6f86bc3076530b6e9ca6443fc75b5 fileName=abc.bin fileType=Zip archive data, at least v2.0 to extract startTime=2015-02-23 17:36:39.841+00',
        '2019-02-23 17:36:39.841+00 tap0.test.cyphort.com CEF:0|Cyphort|Cortex|3.2.1.16|exploit|Exploit|7|externalId=995 eventId=123 lastActivityTime=2015-02-23 17:36:39.841+00 src=50.154.149.189 dst=192.168.1.10 reqReferer=http:// forums.govteen.com/content.php url=http://64.202.116.151/nzrems2/1',
        '2019-12-11 17:36:39.841+00 tap0.test.cyphort.com CEF:0|Cyphort|Cortex|3.2.1.12|http|TROJAN_Zemot.CY|5|eventId=123 src=50.154.149.189 dst=192.168.1.10 startTime=2014-10-30 01:05:16.001+00fileHash=1d81e21db086a2c385696f17f17bdde6d4be04d4 fileName=ccaed7c3c6e58a2844c9896246997f62.bin fileType=PE32 executable (GUI) Intel 80386, for MS Windows startTime=2014-08-11 17:36:39.841+00',
        '2015-04-13 09:45:39.841+00 tap0.test.cyphort.com CEF:0|Cyphort|Cortex|3.2.1.16|submission|TROJAN_Zemot.CY|7|externalId=99 5 eventId=123 lastActivityTime=2015-02-23 17:36:39.841+00 src=50.154.149.189 dst=192.168.1.10 fileHash=d93216633bf6f86bc3076530b6e9ca6443fc75b5 fileName=abc.bin fileType=Zip archive data, at least v2.0 to extract submissionTime=2015- 02-23 17:36:39.841+00',
    ]
    logging.getLogger().addHandler(logging.StreamHandler())
    logging.getLogger().setLevel(logging.DEBUG)

    print "Testing CyphortSyslogMsg"
    for msg in syslog_msgs:
        print '---------------------'
        fsm = CyphortSyslogMsg(msg)
        print 'is_valid: %s' % fsm.is_valid()
        print 'DECODED MSG:\n%s' % fsm.decoded_msg()
        print 'type: %s' % fsm.type
        print 'subtype: %s' % fsm.sub_type
        print 'app: %s' % fsm.app
        print 'app_short: %s' % fsm.app_short
        print 'src_ip: %s' % fsm.src_ip
        print 'dst_ip: %s' % fsm.dst_ip
        # print 'timestamp: %s' % fsm.timestamp
        print 'check timestamp: %s, is_recent: %s' % (fsm.timestamp,
                                                      fsm.is_recent())

if __name__ == "__main__":
    test()
