''' shared settings for DirectFlow Assist for Firewalls
    users will rarely need to change these settings
'''
#
# pylint: disable = line-too-long

import logging
from logging.handlers import SysLogHandler

DFA_PERSIST_ROOT = '/persist/sys/extensions/directflow_assist/'  # include trailing slash
PID_FILENAME = '/var/run/directflow_assist.pid'  # absolute path to pid file
LOG_FILE = '/var/log/directflow_assist.log'      # also change in directflow_assist_logrotate

MIN_LOG_LEVEL = logging.DEBUG           # logging levels: DEBUG, INFO, WARNING
MIN_EOS_VERSION = '4.14.6F'             # min version with req'd "show directflow detail"
SWITCH = {'eapi_protocol': 'unix-socket',  # options: http, https, unix-socket (4.14.5 or later)
          'ip': '127.0.0.1',            # not required when using unix-socket
          'eapi_username': '',          # not required when using unix-socket
          'eapi_password': ''}          # not required when using unix-socket

MIRROR_AFTER_REWRITES = True            # True= 'action egress mirror'
APP_NAME_MAX_CHARS = 9                  # in flow names truncate app name after MAX chars

FLOWMGR_RUN_INTERVAL = 60               # seconds, check and purge inactive and least active flows
TCAM_REAP_THRESHOLD_PCT = 98            # % TCAM utilization to delete least active flows
TCAM_REAP_LEAST_ACTIVE_PCT = 10         # % of flow entries to reap when above threshold, 0 to disable

# If a flow entry does not match any packets within the _FLOW_IDLE_TIMEOUT it will be deleted.
BYPASS_FLOW_IDLE_TIMEOUT = 5            # in minutes, 0 = no idle timeout
DROP_FLOW_IDLE_TIMEOUT = 5              # in minutes, 0 = no idle timeout
REDIRECT_FLOW_IDLE_TIMEOUT = 2          # in minutes, (always used for flow direction sensing idle timeout)

# _FLOW_LIFETIME is the longest period that a flow entry of a given type will be in the TCAM
# Flow lifetime can also be set from a firewall rule name when it ends with "_Nm"
# where N is a number less than FLOW_LIFETIME_MAX in minutes, e.g. "Backup_flow_60m"
BYPASS_FLOW_LIFETIME = 150              # in minutes, consider large file copy/backup times
DROP_FLOW_LIFETIME = 30                 # in minutes
REDIRECT_FLOW_LIFETIME = 30             # in minutes
FLOW_LIFETIME_MAX = 24 * 60             # in minutes
MAX_SYSLOG_MSG_AGE = 5                  # in minutes, ignore messages older than this
SYSLOG_CONN_TIMEOUT = 4 * 60            # in minutes, detect inactive connections

REWRITE_VLAN_ON_EGRESS = False          # for bypass flows
SWITCH_INTERFACE_A_VLAN = 0             # bypass flow rewrite VLAN on egress, 0=no rewrite
SWITCH_INTERFACE_B_VLAN = 0             # bypass flow rewrite VLAN on egress, 0=no rewrite

SYSLOG_PORT = 9514                      # DFA listener L4 port
SYSLOG_SENDER_FACILITY = SysLogHandler.LOG_USER
DFA_LOG_MSGS_TO_SERVER = ('', 0)        # export DFA log msgs to server; tuple (ip, udp_port)

DEDUP_CACHE_ENTRY_LIFETIME = 1          # in minutes
DEDUP_CACHE_MAX_SIZE = 1000             # max number of flow specs in cache, 0= disabled
MONITOR_FLOWS_REFRESH_DEFAULT = 5       # in seconds
MONITOR_FLOWS_MAX_DISPLAY = 20          # as displayed by: ./assist.py monitor
ALLOW_ASYMMETRIC_BYPASSES = True        # in HA mode deployments asymm. bypasses expected, otherwise not
FW_INTF_IN_SYSLOG_MSG = True            # some devices don't provide ingress/egress intf info

OPEN_SYSLOG_UDP_PORT_CMD = 'sudo iptables -A INPUT -p udp --dport %d -j ACCEPT' % SYSLOG_PORT
OPEN_SYSLOG_TCP_PORT_CMD = 'sudo iptables -A INPUT -p tcp --dport %d -j ACCEPT' % SYSLOG_PORT
CLOSE_SYSLOG_UDP_PORT_CMD = 'sudo iptables -D INPUT -p udp --dport %d -j ACCEPT' % SYSLOG_PORT
CLOSE_SYSLOG_TCP_PORT_CMD = 'sudo iptables -D INPUT -p tcp --dport %d -j ACCEPT' % SYSLOG_PORT

# DirectFlow entry priority, higher number takes precedence
PRIORITY_STATIC_PORT_BINDING_FLOW = 10
PRIORITY_REDIRECT_FLOW = 30
PRIORITY_BYPASS_FW_FLOW = 40
PRIORITY_DROP_FLOW = 50

STORM_CONTROL_BCAST_LEVEL = '0.1'       # max broadcast level on intf to/from firewall
STORM_CONTROL_MCAST_LEVEL = '0.1'       # max multicast level on intf to/from firewall

# constants used by other config options and their display strings
UDP, TCP, SSL = 'UDP', 'TCP', 'SSL/TLS'  # define transport options

# operating modes
SHUNT_MODE = 'SHUNT_MODE'               # default traffic through FW, drops & bypasses
INLINE_MODE = 'INLINE_MODE'             # all traffic to FW, drops only
MIRROR_MODE = 'MIRROR_MODE'             # default traffic bypasses FW, drops only
MIRROR_AND_SHUNT_MODE = 'MIRROR_AND_SHUNT_MODE'  # default traffic bypasses FW, drops & redirects

# DFA actions
DROP_FLOW = 'Drop_Flow'
BYPASS_FIREWALL = 'Bypass_FW'
REDIRECT_TO_FIREWALL = 'Redirect_to_FW'
DFA_IGNORE = 'DFA_Ignore'

STATIC_BINDING_FLOWNAME_PREFIX = 'STATIC'
DROP_FLOWNAME_PREFIX = 'DROP'
BYPASS_FLOWNAME_PREFIX = 'BYPASS'
REDIR_FLOWNAME_PREFIX = 'REDIR_TO_FW'

SRC_IP = 'src_ip'
SRC_PORT = 'src_port'
DST_IP = 'dst_ip'
DST_PORT = 'dst_port'
PROTOCOL = 'protocol'
ANY_HOST = '0.0.0.0'
# IGNORE_IP_EPHEMERAL_PORTS = True
# IP_EPHEMERAL_PORTRANGE = (1025, 65535)
