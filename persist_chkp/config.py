''' settings for DirectFlow Assist for Check Point Firewalls
'''
#
# pylint: disable = line-too-long
from config_common import *


OPERATING_MODE = SHUNT_MODE             # SHUNT_MODE, INLINE_MODE, MIRROR_MODE
SYSLOG_TRANSPORT = UDP                  # options: UDP, TCP  (SSL/TLS support coming soon from Check Point)
ACCEPT_SYSLOG_MSGS_FROM_IP = []         # only process msgs from these source IP addresses

# Define switch and firewall interfaces based on the designations show in diagram below:
#    Zone_A  Zone_B
#       |    |
#       A    B                             <-- switch interfaces to network
#  [=========== ARISTA SWITCH ==========::]
#      AF    BF   TO_TAP  HA_AF    HA_BF   <-- switch interfaces to firewall
#       |    |      |       |        |
#      AF    BF    TAP    HA_AF    HA_BF   <-- firewall interfaces to switch
#  [PAN FIREWALL 1]--HA--[PAN FIREWALL 2]
#
# Zone_A interfaces
SWITCH_INTERFACE_A = ''
SWITCH_INTERFACE_AF = ''
SWITCH_INTERFACE_HA_AF = ''             # optional: High-Availability to second firewall
FIREWALL_INTERFACE_AF = ''              # use same firewall intf name on AF and HA_AF, don't include sub-intf

# Zone_B interfaces
SWITCH_INTERFACE_B = ''
SWITCH_INTERFACE_BF = ''
SWITCH_INTERFACE_HA_BF = ''             # optional: High-Availability to second firewall
FIREWALL_INTERFACE_BF = ''              # use same firewall intf name on AF and HA_AF, don't include sub-intf

SWITCH_INTERFACES_TO_FW_TAP = []        # switch interface(s) attached to firewall tap interface(s)
SWITCH_INTERFACES_TO_BE_MIRRORED = []   # only rx/ingress traffic is mirrored, MIRROR_MODE only

# Define Syslog Message Triggers.  A trigger is defined in a python dictionary, where
# each key is a case sensitive syslog message field name and the associated value is a
# case insensitive string or list of strings.  If the string or any string in the list
# is "contained within" the named syslog message field then that key is satisfied.  The
# value string(s) can be a regular expression if more complex matches are required.
# The trigger fires if all keys are satisfied.
DROP_DEFAULT = {'product': 'FireWall', 'Action': ['drop', 'deny']}
BYPASS_DEFAULT = {'product': 'FireWall', 'Action': 'accept'}
DFA_IGNORE_FILTER = {}  # filter here if can't config firewall not to send a particular msg

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
# Available actions: DROP_FLOW, BYPASS_FIREWALL, REDIRECT_TO_FIREWALL, DFA_IGNORE
DFA_CONTROLLER_SPEC = [
    # {'action': DFA_IGNORE, 'trigger': DFA_IGNORE_FILTER},  # process ignores first
    {'action': DROP_FLOW, 'flow_match': SRC_IP_DST_IP_PORT, 'trigger': DROP_DEFAULT},
    {'action': BYPASS_FIREWALL, 'flow_match': FIVE_TUPLE, 'trigger': BYPASS_DEFAULT}]

# set/mark Ethernet CoS and/or IP ToS fields in bypassed flows; higher value = higher priority
# COS range <0-7>; TOS range <0-255>  uses the 6 most significant bits of this byte
# key= application name string from FW syslog, value is a dict with key='COS' and/or 'TOS' value=integer
COS_TOS_MARKING = {
    'echo_request_DFA': {'COS': 3, 'TOS': 8},
    'ssh_DFA': {'TOS': 16}}

# Check Point package specific settings
APP_NAME = 'DirectFlow Assist for Check Point Firewalls'
SSL_CA_CERTS_FILE = DFA_PERSIST_ROOT + 'rootCA2.crt'
SSL_DFA_CERT_FILE = DFA_PERSIST_ROOT + 'dfa.crt'
SSL_DFA_KEY_FILE = DFA_PERSIST_ROOT + 'dfa.key'

FW_INTF_IN_SYSLOG_MSG = False           # as of R77_30 firewall ingress/egress intf not in syslog msg
BYPASS_FLOW_IDLE_TIMEOUT = 2            # in minutes, also used for flow direction sensing idle timeout
ASSIST_WHEN_SERVICE_ID_SUFFIX = '_DFA'  # suffix on service_id field to indicate DFA should assist


def get_msg_class():
    ''' runtime import
    '''
    from directflow_assist import CheckPointSyslogMsg
    return CheckPointSyslogMsg.CheckPointSyslogMsg
