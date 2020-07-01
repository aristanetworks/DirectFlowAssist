''' settings for DirectFlow Assist for Palo Alto Networks Firewalls
'''
#
# pylint: disable = line-too-long
from config_common import *


OPERATING_MODE = INLINE_MODE            # SHUNT_MODE, INLINE_MODE, MIRROR_MODE, MIRROR_AND_SHUNT_MODE
SYSLOG_TRANSPORT = UDP                  # options: UDP, TCP, SSL
ACCEPT_SYSLOG_MSGS_FROM_IP = ['172.20.24.15']   # only process msgs from these source IP addresses

# Define switch and firewall interfaces based on the operating mode:
#  Zone_A    Zone_B
#       |    |
#       A    B                              <-- switch interfaces to network
#  [=========== ARISTA SWITCH ==========::]
#     AF    BF  TO_FW_TAP  HA_AF    HA_BF   <-- switch interfaces to firewall
#      |    |       |        |        |
#     AF    BF     TAP     HA_AF    HA_BF   <-- firewall interfaces to switch
#   [  FIREWALL 1  ]--HA--[  FIREWALL 2  ]
#
# Zone_A interfaces
SWITCH_INTERFACE_A = 'Ethernet1'
SWITCH_INTERFACE_AF = 'Ethernet2'
SWITCH_INTERFACE_HA_AF = 'Ethernet3'           # optional: High-Availability to second firewall
FIREWALL_INTERFACE_AF = 'ethernet1/1'   # use same firewall intf name on AF and HA_AF, don't include sub-intf

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
SPYWARE_CMD_AND_CTRL = {  # botnet command-and-control (C&C) server communications
    'Type': 'THREAT', 'Action': 'reset-both',
    'Threat/Content Type': 'spyware',
    'Threat/Content Name': 'Command and Control'}

VIRUS_EICAR_FILE = {  # European Institute for Computer Antivirus Research test file
    'Type': 'THREAT', 'Action': 'deny',
    'Threat/Content Type': 'virus',
    'Threat/Content Name': 'Eicar Test File'}

VULNERABILITY_INFO_DISCLOSURE = {
    'Type': 'THREAT', 'Action': 'reset-server',
    'Threat/Content Type': 'vulnerability',
    'Threat/Content Name': 'Information Disclosure Vulnerability'}

TCP_FLOOD_ATTACK = {
    'Type': 'THREAT',
    'Action': ['^drop$',       # match whole field, don't want to match 'random-drop'
               'drop-all-packets'],
    'Threat/Content Type': 'flood',
    'Threat/Content Name': 'TCP Flood'}

THREAT_DROP_DEFAULT = {
    'Type': 'THREAT',
    'Action': ['^drop$',       # match whole field, don't want to match 'random-drop'
               'drop-all-packets', 'deny', 'block-url', 'reset-(client|server|both)']}

TRAFFIC_DROP_DEFAULT = {'Type': 'TRAFFIC', 'Action': 'deny'}

BYPASS_DEFAULT = {'Type': 'TRAFFIC', 'Action': 'allow'}

DFA_IGNORE_FILTER = {  # filter here if can't config firewall not to send a particular msg
    'Threat/Content Name': ['DNS Query']}   # always require DPI from firewall

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
    {'action': DFA_IGNORE, 'trigger': DFA_IGNORE_FILTER},   # process ignores first
    {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': SPYWARE_CMD_AND_CTRL},
    {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': VULNERABILITY_INFO_DISCLOSURE},
    {'action': DROP_FLOW, 'flow_match': SRC_IP_ONLY, 'trigger': TCP_FLOOD_ATTACK},
    {'action': DROP_FLOW, 'flow_match': SRC_IP_DST_IP, 'trigger': VIRUS_EICAR_FILE},
    {'action': DROP_FLOW, 'flow_match': SRC_IP_DST_IP_PORT, 'trigger': THREAT_DROP_DEFAULT},
    {'action': DROP_FLOW, 'flow_match': SRC_IP_DST_IP_PORT, 'trigger': TRAFFIC_DROP_DEFAULT},
    {'action': BYPASS_FIREWALL, 'flow_match': FIVE_TUPLE, 'trigger': BYPASS_DEFAULT}]

# set/mark Ethernet CoS and/or IP ToS fields in bypassed flows; higher value = higher priority
# COS range <0-7>; TOS range <0-255>  uses the 6 most significant bits of this byte
# key= app name from syslog msg, value is a dict with key='COS' and/or 'TOS', value= integer
COS_TOS_MARKING = {
    'ssh': {'TOS': 16},
    'web-browsing': {'COS': 2},
    'ping': {'COS': 3, 'TOS': 8}}

# Palo Alto Networks package specific settings
APP_NAME = 'DirectFlow Assist for PAN Firewalls'
SSL_CA_CERTS_FILE = DFA_PERSIST_ROOT + 'rootCA2.crt'
SSL_DFA_CERT_FILE = DFA_PERSIST_ROOT + 'dfa.crt'
SSL_DFA_KEY_FILE = DFA_PERSIST_ROOT + 'dfa.key'

# PAN-OS 6.0 comma-separated value (CSV) string syslog message field definitions
PAN_SYSLOG_FIELD_LABELS = {
    'TRAFFIC': [
        'Domain', 'Receive Time', 'Serial #', 'Type', 'Threat/Content Type',
        'Config Version', 'Generate Time', 'Source address',
        'Destination address', 'NAT Source IP', 'NAT Destination IP', 'Rule',
        'Source User', 'Destination User', 'Application', 'Virtual System',
        'Source Zone', 'Destination Zone', 'Inbound Interface',
        'Outbound Interface', 'Log Action', 'Time Logged', 'Session ID',
        'Repeat Count', 'Source Port', 'Destination Port', 'NAT Source Port',
        'NAT Destination Port', 'Flags', 'IP Protocol', 'Action', 'Bytes',
        'Bytes Sent', 'Bytes Received', 'Packets', 'Start Time',
        'Elapsed Time (sec)', 'Category', 'Padding', 'seqno', 'actionflags',
        'Source Country', 'Destination Country', 'cpadding', 'pkts_sent',
        'pkts_received'],

    'THREAT': [
        'Domain', 'Receive Time', 'Serial #', 'Type', 'Threat/Content Type',
        'Config Version', 'Generate Time', 'Source address',
        'Destination address', 'NAT Source IP', 'NAT Destination IP', 'Rule',
        'Source User', 'Destination User', 'Application', 'Virtual System',
        'Source Zone', 'Destination Zone', 'Inbound Interface',
        'Outbound Interface', 'Log Action', 'Time Logged', 'Session ID',
        'Repeat Count', 'Source Port', 'Destination Port', 'NAT Source Port',
        'NAT Destination Port', 'Flags', 'IP Protocol', 'Action', 'URL',
        'Threat/Content Name', 'Category', 'Severity', 'Direction', 'seqno',
        'actionflags', 'Source Country', 'Destination Country', 'cpadding',
        'contenttype', 'pcap_id', 'filedigest', 'cloud']
}


def get_msg_class():
    ''' runtime import '''
    from directflow_assist import PANSyslogMsg
    return PANSyslogMsg.PANSyslogMsg
