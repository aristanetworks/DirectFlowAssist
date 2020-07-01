#!/usr/bin/env python2.7
#
# Copyright (c) 2014-2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#

''' Utility functions for DirectFlow Assist
'''

import os
import os.path
import logging

from directflow_assist.common import utils
from .__init__ import __version__
import config


def pid_filename():
    ''' returns process id file name
    '''
    return config.PID_FILENAME


def create_pid_file():
    ''' creates process id file
    '''
    pid_file = open(pid_filename(), 'w')
    pid_file.write(str(os.getpid()))
    pid_file.close()


def delete_pid_file():
    ''' removes process id file
    '''
    if os.path.exists(pid_filename()):
        os.remove(pid_filename())


def pid_file_exists():
    ''' check exists
    '''
    return os.path.exists(pid_filename())


def pid_process_running():
    ''' return True if running
    '''
    if pid_file_exists():
        pidfile = open(pid_filename())
        pid = pidfile.read().strip()
        if os.path.exists("/proc/" + pid):
            return True
    return False


def start_logging():
    ''' create log file
    '''
    utils.setup_logging(config.LOG_FILE, config.MIN_LOG_LEVEL)
    (server_ip, udp_port) = config.DFA_LOG_MSGS_TO_SERVER
    if server_ip and udp_port:
        utils.setup_logging_to_external_syslog_server(server_ip, udp_port)
    app_id = config.APP_NAME + " " + __version__
    logging.info('**** logging started for: %s', app_id)
    logging.info(utils.get_exec_envt())
    return True


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
