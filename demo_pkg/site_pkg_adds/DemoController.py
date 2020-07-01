#!/usr/bin/env python2.7
#
# Copyright (c) 2014-2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#

''' DFA Demo command listener and controller
'''

import time
import threading
import logging
import SocketServer
import SyslogListener
import DirectFlowSwitch
import util
from common import utils
import config


class DemoCmdServer(SocketServer.BaseRequestHandler):
    ''' receives pause/resume/delete commands from demo GUI
    '''
    def handle(self):
        ''' handle msg
        '''
        cmd = self.request[0].strip()
        _socket = self.request[1].getsockname()
        logging.debug('\nReceived cmd msg: [%s] on port %s from %s',
                      cmd, _socket[1], self.client_address[0])
        try:
            if cmd == 'DFA_CMD_PAUSE':
                SyslogListener.MSG_HANDLER.pause_processing()

            elif cmd == 'DFA_CMD_RESUME':
                SyslogListener.MSG_HANDLER.resume_processing()

            elif cmd == 'DFA_CMD_DELETE_FLOWS':
                SyslogListener.MSG_HANDLER.clear_flow_spec_cache()
                dfs = DirectFlowSwitch.get_directflow_switch()
                dfs.delete_dynamic_flows()

            else:
                logging.warning('Ignoring unknown command: %s', cmd)
        except Exception as exc:
            logging.exception('Error in DemoCmdServer: %s', exc)


class DemoController(object):
    ''' main entry point for DFA demo
    '''
    def startup(self):
        ''' start here
        '''
        try:
            utils.setup_logging(config.LOG_FILE, logging.DEBUG)
            logging.info('**** DemoController logging started')
            # start DirectFlow Assist thread
            dfa_thread = threading.Thread(target=SyslogListener.main)
            dfa_thread.start()
            logging.info('SyslogListener started')
            time.sleep(2)

            utils.exec_shell_cmd(config.OPEN_DEMO_CTRL_PORT_CMD)
            cmd_server = SocketServer.UDPServer(
                (config.ANY_HOST, config.DEMO_CTRL_UDP_PORT), DemoCmdServer)
            cmd_server_thread = threading.Thread(
                target=cmd_server.serve_forever)
            # cmd_server_thread.daemon = True
            cmd_server_thread.start()
            logging.info('Listening for demo control msgs on port: %d',
                         config.DEMO_CTRL_UDP_PORT)

            while util.pid_file_exists():  # main thread waits here
                time.sleep(2)

        except KeyboardInterrupt:
            logging.info('DirectFlow Assist demo command listener exiting.')
        except Exception as exc:
            logging.exception('Error in DemoController: %s', exc)
        finally:
            logging.info('Shutting down DemoController listener on port: %d',
                         config.DEMO_CTRL_UDP_PORT)
            cmd_server.shutdown()
            utils.exec_shell_cmd(config.CLOSE_DEMO_CTRL_PORT_CMD)
            logging.info('DemoController has stopped')
