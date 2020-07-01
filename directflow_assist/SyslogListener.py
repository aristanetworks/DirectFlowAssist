#!/usr/bin/env python2.7
#
# Copyright (c) 2013-2015 Arista Networks, Inc.  All rights reserved
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = wildcard-import, unused-wildcard-import, too-many-branches
# pylint: disable = broad-except

''' Listens for incoming syslog messages from firewall
'''

import os
import threading
import logging
import time
import SocketServer
import socket
import ssl
import config
from . import util
from directflow_assist.common import utils

# from .__init__ import __version__
from .FlowAssistController import FlowAssistController
from .FlowEntryManager import FlowEntryMgr

MSG_HANDLER = FlowAssistController()
MSG_HANDLER_LOCK = threading.Lock()


class MyUDPServer(SocketServer.UDPServer):
    ''' override just to set socket reuse
    '''
    allow_reuse_address = True


class UDPSyslogHandler(SocketServer.BaseRequestHandler):
    ''' handler for syslog messages over UDP connection
    '''
    allow_reuse_address = True

    def handle(self):
        try:
            if not is_valid_firewall_ip(self.client_address[0]):
                return
            logging.info('++ UDPSyslogHandler [%s] received msg from: %s',
                         threading.current_thread().name, self.client_address)
            msg = self.request[0].strip()
            MSG_HANDLER_LOCK.acquire()
            MSG_HANDLER.process_msg(msg)
            MSG_HANDLER_LOCK.release()
        except Exception as exc:
            logging.exception('UDPSyslogHandler.handle(): %s', exc)
        finally:
            if MSG_HANDLER_LOCK.locked():
                MSG_HANDLER_LOCK.release()
                # logging.debug('UDPSyslogHandler %s released MSG_HANDLER_LOCK!',
                #              threading.current_thread().name)


class ThreadedTCPSyslogServer(SocketServer.ThreadingMixIn,
                              SocketServer.TCPServer):
    ''' handler for syslog messages over plain TCP connection
        this class def adds ThreadingMixIn
    '''
    allow_reuse_address = True


class ThreadedSSLSyslogServer(ThreadedTCPSyslogServer):
    ''' handler for syslog messages over SSL wrapped TCP connection
    '''
    def __init__(self, (host, port), handler):
        SocketServer.TCPServer.__init__(self, (host, port), handler,
                                        bind_and_activate=False)
        logging.debug('ThreadedSSLSyslogServer wrapping TCP socket in SSL')
        self.socket = ssl.wrap_socket(
            self.socket,
            keyfile=config.SSL_DFA_KEY_FILE,  # identify local side of conn
            certfile=config.SSL_DFA_CERT_FILE,  # identify local side of conn
            ca_certs=config.SSL_CA_CERTS_FILE,  # CAs to validate client certs
            cert_reqs=ssl.CERT_REQUIRED,
            ssl_version=ssl.PROTOCOL_TLSv1,  # SSLv3, TLSv1, TLSv1_1, TLSv1_2
            server_side=True)
        self.server_bind()
        self.server_activate()
        logging.debug('ThreadedSSLSyslogServer SSL wrap_socket complete')


class TCPSyslogHandler(SocketServer.StreamRequestHandler):
    ''' handler for syslog messages over TCP connection
    '''
    timeout = config.SYSLOG_CONN_TIMEOUT * 60  # in seconds

    def handle(self):
        try:
            if not is_valid_firewall_ip(self.client_address[0]):
                return
            logging.info('+++ SyslogHandler [%s] accepted %s conn from: %s',
                         threading.current_thread().name, config.SYSLOG_TRANSPORT,
                         self.client_address)
            while True:
                logging.debug('SyslogHandler waiting for msg from: %s',
                              self.client_address)
                msg = self.rfile.readline().strip()
                logging.info('<> SyslogHandler: received msg length: %s, '
                             'from: %s', len(msg), self.client_address)
                if len(msg) == 0:
                    logging.info('EOF socket is closed')
                    break
                else:
                    MSG_HANDLER_LOCK.acquire()
                    # logging.debug('SyslogHandler %s has MSG_HANDLER_LOCK',
                    #              threading.current_thread().name)
                    MSG_HANDLER.process_msg(msg)
                    # logging.debug('SyslogHandler %s released MSG_HANDLER_LOCK',
                    #              threading.current_thread().name)
                    MSG_HANDLER_LOCK.release()

        except socket.timeout:
            logging.info('-- SyslogHandler [%s] %s connection timeout',
                         threading.current_thread().name, self.client_address)
        except ssl.SSLError as sslexc:  # SSL throws different timeout exception
            if 'read operation timed out' in sslexc.message:
                logging.info('-- SyslogHandler [%s] SSL %s connection timeout',
                             threading.current_thread().name,
                             self.client_address)
            else:
                logging.exception('SyslogHandler.handle() SSLError: %s', exc)
        except Exception as exc:
            logging.exception('SyslogHandler.handle(): %s', exc)
        finally:
            if MSG_HANDLER_LOCK.locked():
                MSG_HANDLER_LOCK.release()
                logging.debug('TCPSyslogHandler %s released MSG_HANDLER_LOCK!',
                              threading.current_thread().name)
            logging.info('-- SyslogHandler [%s] %s shutdown & close connection',
                         threading.current_thread().name, self.client_address)
            self.connection.shutdown(socket.SHUT_RDWR)
            time.sleep(1)
            self.connection.close()
            logging.debug('-- SyslogHandler close connection complete')


def is_valid_firewall_ip(ip_addr):
    ''' validate config
    '''
    if ip_addr in config.ACCEPT_SYSLOG_MSGS_FROM_IP:
        return True
    else:
        logging.warning('** %s attempted to connect to DFA syslog listener',
                        ip_addr)
        return False


def validate_ssl_files():
    ''' ensure key files exist
    '''
    if not os.path.exists(config.SSL_CA_CERTS_FILE):
        raise Exception('SSL_CA_CERTS_FILE %s not found' % config.SSL_CA_CERTS_FILE)
    elif not os.path.exists(config.SSL_DFA_CERT_FILE):
        raise Exception('SSL_DFA_CERT_FILE %s not found' % config.SSL_DFA_CERT_FILE)
    elif not os.path.exists(config.SSL_DFA_KEY_FILE):
        raise Exception('SSL_DFA_KEY_FILE %s not found' % config.SSL_DFA_KEY_FILE)


def main():
    ''' main entry point for DirectFlow Assist syslog listener
    '''
    syslog_listener = None
    flow_entry_mgr = None
    try:
        util.start_logging()
        util.create_pid_file()
        logging.info('Listening for firewall syslog msgs on %s port: %d',
                     config.SYSLOG_TRANSPORT, config.SYSLOG_PORT)
        if config.SYSLOG_TRANSPORT == config.UDP:
            utils.exec_shell_cmd(config.OPEN_SYSLOG_UDP_PORT_CMD)
            syslog_listener = MyUDPServer((config.ANY_HOST, config.SYSLOG_PORT),
                                          UDPSyslogHandler)
        elif (config.SYSLOG_TRANSPORT == config.TCP or
              config.SYSLOG_TRANSPORT == config.SSL):
            utils.exec_shell_cmd(config.OPEN_SYSLOG_TCP_PORT_CMD)
            logging.info('SYSLOG_CONN_TIMEOUT: %s min.', config.SYSLOG_CONN_TIMEOUT)
            if config.SYSLOG_TRANSPORT == config.TCP:
                syslog_listener = ThreadedTCPSyslogServer(
                    (config.ANY_HOST, config.SYSLOG_PORT), TCPSyslogHandler)
            else:  # SSL
                validate_ssl_files()
                syslog_listener = ThreadedSSLSyslogServer(
                    (config.ANY_HOST, config.SYSLOG_PORT), TCPSyslogHandler)
        else:
            raise Exception('unknown/unsupported SYSLOG_TRANSPORT')

        # start listener thread(s), 1 for UDP, TCP/SSL will have 1 main server
        # plus 1 thread for each firewall (e.g. 1 + 2 with HA mode FWs)
        syslog_listener_thread = threading.Thread(
            target=syslog_listener.serve_forever)
        syslog_listener_thread.setDaemon(True)
        syslog_listener_thread.start()

        # start FlowEntryMgr thread
        flow_entry_mgr = FlowEntryMgr()
        flow_entry_mgr.setDaemon(True)
        flow_entry_mgr.start()

        while util.pid_file_exists():  # main thread waits here
            time.sleep(2)

    except KeyboardInterrupt:
        print '\nDirectFlow Assist exiting'
    except Exception as exc:
        logging.exception(exc)
        print 'Error: %s' % exc
    finally:
        logging.info('DFA shutting down...')
        if flow_entry_mgr:
            flow_entry_mgr.stop_running()
        shutdown_msg = 'Stopping syslog listener on port: %d' % config.SYSLOG_PORT
        print shutdown_msg
        logging.info(shutdown_msg)
        if syslog_listener and config.SYSLOG_TRANSPORT != config.UDP:
            syslog_listener.socket.shutdown(socket.SHUT_RDWR)
        if config.SYSLOG_TRANSPORT == config.UDP:
            utils.exec_shell_cmd(config.CLOSE_SYSLOG_UDP_PORT_CMD)
        else:
            utils.exec_shell_cmd(config.CLOSE_SYSLOG_TCP_PORT_CMD)

        util.delete_pid_file()  # ensure pid file removed
        time.sleep(5)     # give connections time to close and write logs, etc.
        print 'DFA has stopped'
