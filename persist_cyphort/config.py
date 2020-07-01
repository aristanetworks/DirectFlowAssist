''' settings for DirectFlow Assist for Cyphort
'''
#
# pylint: disable = line-too-long
from config_common import *

OPERATING_MODE = MIRROR_MODE            # modes supported: MIRROR_MODE
SYSLOG_TRANSPORT = UDP                  # options: UDP, TCP, SSL
ACCEPT_SYSLOG_MSGS_FROM_IP = []         # only process msgs from these source IP addresses

SWITCH_INTERFACES_TO_FW_TAP = []        # switch interface(s) attached to MDS tap interface(s)
SWITCH_INTERFACES_TO_BE_MIRRORED = []   # only rx/ingress traffic is mirrored, MIRROR_MODE only

# Define Syslog Message Triggers.  A trigger is defined in a python dictionary, where
# each key is a case sensitive syslog message field name and the associated value is a
# case insensitive string or list of strings.  If the string or any string in the list
# is "contained within" the named syslog message field then that key is satisfied.  The
# value string(s) can be a regular expression if more complex matches are required.
# The trigger fires if all keys are satisfied.
DFA_IGNORE_FILTER = {}  # filter here if can't config firewall not to send a particular msg
CMD_AND_CTRL_TRIGGER = {'type': 'cnc'}
DATATHEFT_TRIGGER = {'type': 'datatheft'}
EMAIL_TRIGGER = {'type': 'email'}
EXPLOIT_TRIGGER = {'type': 'exploit'}
HTTP_TRIGGER = {'type': 'http'}
SUBMISSION_TRIGGER = {'type': 'submission'}

# Flow match criteria used by DirectFlow in switch TCAM.  The value for each field
# is extracted from the triggering syslog message.  Define sensible combinations of
# these 5-tuple fields: SRC_IP, SRC_PORT, DST_IP, DST_PORT, PROTOCOL.
SRC_IP_DST_IP = [SRC_IP, DST_IP]
SRC_IP_ONLY = [SRC_IP]

# Combine syslog message triggers, assist actions and DirectFlow flow match criteria
# into a specification for DFA controller.  When a firewall syslog message is
# received triggers are processed in the order defined here.  Define defaults last.
# Available actions: DROP_FLOW, BYPASS_FIREWALL, REDIRECT_TO_FIREWALL, DFA_IGNORE
DFA_CONTROLLER_SPEC = [
    {'action': DFA_IGNORE, 'trigger': DFA_IGNORE_FILTER},      # ignore filter first
    {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': CMD_AND_CTRL_TRIGGER},
    {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': DATATHEFT_TRIGGER},
    {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': EMAIL_TRIGGER},
    {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': EXPLOIT_TRIGGER},
    {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': HTTP_TRIGGER},
    {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': SUBMISSION_TRIGGER},
]
# DFA_CONTROLLER_SPEC = [
#     {'action': DFA_IGNORE, 'trigger': DFA_IGNORE_FILTER},      # ignore filter first
#     {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': {'type': 'cnc'}},
#     {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': {'type': 'datatheft'}},
#     {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': {'type': 'exploit'}},
#     {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': {'type': 'submission'}},
# ]

# set/mark Ethernet CoS and/or IP ToS fields in bypassed flows; higher value = higher priority
# COS range <0-7>; TOS range <0-255>  uses the 6 most significant bits of this byte
# key= application field string from firewall syslog msg, value is COS and/or TOS value to be set
COS_TOS_MARKING = {}

# Cyphort package specific settings
APP_NAME = 'DirectFlow Assist for Cyphort Malware Defense System'
SSL_CA_CERTS_FILE = DFA_PERSIST_ROOT + 'rootCA2.crt'
SSL_DFA_CERT_FILE = DFA_PERSIST_ROOT + 'dfa.crt'
SSL_DFA_KEY_FILE = DFA_PERSIST_ROOT + 'dfa.key'
APP_NAME_MAX_CHARS = 30  # in flow names truncate app name after MAX chars; override config_common

# unused settings with Cyphort tap only
SWITCH_INTERFACE_A = ''
SWITCH_INTERFACE_AF = ''
SWITCH_INTERFACE_HA_AF = ''
FIREWALL_INTERFACE_AF = ''
SWITCH_INTERFACE_B = ''
SWITCH_INTERFACE_BF = ''
SWITCH_INTERFACE_HA_BF = ''
FIREWALL_INTERFACE_BF = ''


def get_msg_class():
    ''' runtime import '''
    from directflow_assist import CyphortSyslogMsg
    return CyphortSyslogMsg.CyphortSyslogMsg
