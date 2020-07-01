''' settings for DirectFlow Assist for vArmour
'''
# pylint: disable = line-too-long
from config_common import *


OPERATING_MODE = SHUNT_MODE             # SHUNT_MODE, INLINE_MODE, MIRROR_MODE, MIRROR_AND_SHUNT_MODE
SYSLOG_TRANSPORT = UDP                  # options: UDP, TCP, SSL
ACCEPT_SYSLOG_MSGS_FROM_IP = []         # only process msgs from these source IP addresses

# Define switch and firewall interfaces based on the operating mode:
#  Zone_A    Zone_B
#       |    |
#       A    B      <-- switch interfaces to network
#  [ ARISTA SWITCH ]
#      AF    BF     <-- switch interfaces to EP
#       |    |
#      AF    BF     <-- EP interfaces to switch
#   [ vArmour EP ]
#
# Zone_A interfaces
SWITCH_INTERFACE_A_VLAN = 0             # bypass flow rewrite VLAN on egress, 0=no rewrite
SWITCH_INTERFACE_A = ''
SWITCH_INTERFACE_AF = ''
FIREWALL_INTERFACE_AF = ''              # do not include sub-interface, if any
# Zone_B interfaces
SWITCH_INTERFACE_B_VLAN = 0             # bypass flow rewrite VLAN on egress, 0=no rewrite
SWITCH_INTERFACE_B = ''
SWITCH_INTERFACE_BF = ''
FIREWALL_INTERFACE_BF = ''              # do not include sub-interface, if any

SWITCH_INTERFACE_HA_AF = ''
SWITCH_INTERFACE_HA_BF = ''
SWITCH_INTERFACES_TO_FW_TAP = []        # switch interface(s) attached to firewall tap interface(s)
SWITCH_INTERFACES_TO_BE_MIRRORED = []   # only rx/ingress traffic is mirrored, MIRROR_MODE only

# common_config overrides
REWRITE_VLAN_ON_EGRESS = True           # for bypass flows
BYPASS_FLOW_LIFETIME = 5                # in minutes,
DROP_FLOW_LIFETIME = 5                  # in minutes
MAX_SYSLOG_MSG_AGE = 240                # in minutes, ignore messages older than this


# Define Syslog Message Triggers.  A trigger is defined in a python dictionary, where
# each key is a case sensitive syslog message field name and the associated value is a
# case insensitive string or list of strings.  If the string or any string in the list
# is "contained within" the named syslog message field then that key is satisfied.  The
# value string(s) can be a regular expression if more complex matches are required.
# The trigger fires if all keys are satisfied.
DROP_TRIGGER = {'sess-close-reason': 'policy-deny'}
BYPASS_TRIGGER = {'sess-close-reason': 'policy-permit'}

# Flow match criteria used by DirectFlow in switch TCAM.  The value for each field
# is extracted from the triggering syslog message.  Define sensible combinations of
# these 5-tuple fields: SRC_IP, SRC_PORT, DST_IP, DST_PORT, PROTOCOL.
FIVE_TUPLE = [SRC_IP, SRC_PORT, DST_IP, DST_PORT, PROTOCOL]
SRC_IP_DST_IP_PORT = [SRC_IP, DST_IP, DST_PORT, PROTOCOL]
SRC_IP_DST_IP = [SRC_IP, DST_IP]
SRC_IP_ONLY = [SRC_IP]

# Combine syslog message triggers, assist actions and DirectFlow flow match criteria
# into a specification for DFA controller.  When a firewall syslog message is
# received triggers are processed in the order defined here.  Define defaults last.
# Available actions: DROP_FLOW, BYPASS_FIREWALL, DFA_IGNORE
DFA_CONTROLLER_SPEC = [
    {'trigger': DROP_TRIGGER, 'action': DROP_FLOW, 'flow_match': SRC_IP_DST_IP_PORT},
    {'trigger': BYPASS_TRIGGER, 'action': BYPASS_FIREWALL, 'flow_match': FIVE_TUPLE}]

# set/mark Ethernet CoS and/or IP ToS fields in bypassed flows; higher value = higher priority
# COS range <0-7>; TOS range <0-255>  uses the 6 most significant bits of this byte
# key= app name from syslog msg, value is a dict with key='COS' and/or 'TOS', value= integer
COS_TOS_MARKING = {}

# vArmour package specific settings
APP_NAME = 'DirectFlow Assist for vArmour'
SSL_CA_CERTS_FILE = DFA_PERSIST_ROOT + 'rootCA2.crt'
SSL_DFA_CERT_FILE = DFA_PERSIST_ROOT + 'dfa.crt'
SSL_DFA_KEY_FILE = DFA_PERSIST_ROOT + 'dfa.key'


def get_msg_class():
    ''' runtime import '''
    from directflow_assist import VarmourSyslogMsg
    return VarmourSyslogMsg.VarmourSyslogMsg
