#!/usr/bin/env python2.7
#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = line-too-long
''' UDP syslog message sender
'''

import logging
from logging.handlers import SysLogHandler
import socket
import time

SYSLOG_SERVER = '172.22.28.37'
SYSLOG_UDP_PORT = 9514

SLEEP_INTERVAL = 10   # seconds

SYSLOG_FILENAME = './tools/data/varmour_syslogs.dat'
# SYSLOG_FILENAME = './persist_cyphort/syslog_samples.dat'


class UDPSocketSender(object):
    ''' UDP datagram (connection-less) socket sender
    '''
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                    socket.IPPROTO_UDP)

    def send_datagram(self, msg, host, port):
        self.socket.sendto(msg, (host, port))

    def close(self):
        self.socket.close()


def load_from_file(filename):
    ''' loads non-comment lines from a data file into a list and returns it
    '''
    comment_delimiter = '#'
    lines = []
    with open(filename) as data_file:
        for line in data_file:
            line = line.strip()
            if line.startswith(comment_delimiter) or len(line) == 0:
                continue
            lines.append(line)
    return lines


def main():
    print 'Syslog Message Sender'
    sender = UDPSocketSender()
    syslog_msgs = load_from_file(SYSLOG_FILENAME)
    print 'loaded %d syslog msgs from file: %s\n' % (len(syslog_msgs), SYSLOG_FILENAME)
    for msg in syslog_msgs:
        print 'sending msg=%s\n' % msg
        sender.send_datagram(msg, SYSLOG_SERVER, SYSLOG_UDP_PORT)
        time.sleep(SLEEP_INTERVAL)
    sender.close()
    print 'done'


if __name__ == "__main__":
    main()

# alternative sender
#     syslog = SysLogHandler(address=(SYSLOG_SERVER, SYSLOG_PORT),
#                            socktype= socket.SOCK_DGRAM,
#                            facility= SysLogHandler.LOG_USER)
#     logger = logging.getLogger()
#     logger.addHandler(syslog)
#     logger.setLevel(logging.INFO)
#
#     print '\nSending msgs to syslog server %s on port: %d' % (SYSLOG_SERVER, SYSLOG_PORT)
#     for msg in MESSAGES:
#         logging.info(msg)
#         time.sleep(5)
