#!/usr/bin/env python2.7
#
# Copyright (c) 2014-2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.

''' for testing demo controller
'''

import sys
import socket
import time

DEMO_CTRL_UDP_PORT = 9515
DFA_DEMO_SWITCH_IP = "127.0.0.1"


def pause(ip_addr):
    ''' stop processing new syslog messages
    '''
    send_datagram('DFA_CMD_PAUSE', ip_addr)


def resume(ip_addr):
    ''' resume processing new syslog messages
    '''
    send_datagram('DFA_CMD_RESUME', ip_addr)


def delete(ip_addr):
    ''' delete existing DROP and BYPASS flow entries
    '''
    send_datagram('DFA_CMD_DELETE_FLOWS', ip_addr)


def send_datagram(msg, ip_addr):
    ''' send msg
    '''
    udp_socket = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    print ('sending msg: %s to %s on UDP port %d' %
          (msg, ip_addr, DEMO_CTRL_UDP_PORT))
    udp_socket.sendto(msg, (ip_addr, DEMO_CTRL_UDP_PORT))
    udp_socket.close()


def test():
    ''' test
    '''
    test_ip = '172.22.28.38'
    print 'testing ...'
    pause(test_ip)
    time.sleep(20)
    delete(test_ip)
    time.sleep(5)
    resume(test_ip)


def main():
    ''' main
    '''
    if len(sys.argv) == 3:
        ip_addr = sys.argv[1]
        cmd = sys.argv[2]
        if cmd in globals():
            return globals()[cmd](ip_addr)
    print 'usage: python DemoRemote.py ip_addr pause|resume|delete'


if __name__ == '__main__':
    main()
