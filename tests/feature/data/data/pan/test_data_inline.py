import os
import sys

path = os.path.dirname(os.path.realpath(__file__))
pythonpath = path.rpartition('/')[0]
sys.path.append(pythonpath)

import config_common 
import pan.config_inline as config_inline 

SYSLOG_TO_FLOWS_LATENCY = 3
NUM_STATIC_FLOWS = 2

IP1 = '1.1.1.1'
IP2 = '2.2.2.2'
TCP = 6
UDP = 17
ICMP = 1 
IP_PORT_SRC = 100
IP_PORT_DST = 200
timeout = '10m'
intfA = config_inline.SWITCH_INTERFACE_A
if intfA.startswith('e'): intfA = 'Ethernet' + intfA[-1]
intfAF = config_inline.SWITCH_INTERFACE_AF
if intfAF.startswith('e'): intfAF = 'Ethernet' + intfAF[-1]
intfHA_AF = config_inline.SWITCH_INTERFACE_HA_AF
if intfHA_AF.startswith('e'): intfHA_AF = 'Ethernet' + intfHA_AF[-1]
intfB = config_inline.SWITCH_INTERFACE_B
if intfB.startswith('e'): intfB = 'Ethernet' + intfB[-1]
intfBF = config_inline.SWITCH_INTERFACE_BF
if intfBF.startswith('e'): intfBF = 'Ethernet' + intfBF[-1]
intfHA_BF = config_inline.SWITCH_INTERFACE_HA_BF
if intfHA_BF.startswith('e'): intfHA_BF = 'Ethernet' + intfHA_BF[-1]

tests = [
    {'test_name': 'pan_inline_mode_static_flow',
     'input_syslog_msg': '',
     'num_entries': NUM_STATIC_FLOWS,
     'get_flows': 'STATIC.*',
     'output_directflow_entries': [
         {'flow_name_regex': 'STATIC_TO_FIREWALL__in:%s__out:%s_%s' %(config_inline.SWITCH_INTERFACE_A, config_inline.SWITCH_INTERFACE_AF, config_inline.SWITCH_INTERFACE_HA_AF),
          'priority': config_common.PRIORITY_STATIC_PORT_BINDING_FLOW,
          'persistent': True,
          'hardTimeout': 0,
          'idleTimeout': 0,
          'match': {'inInterfaces': [intfA]},
          'action':{'outInterfaces': [intfAF, intfHA_AF]}},
         
         {'flow_name_regex': 'STATIC_TO_FIREWALL__in:%s_%s__out:%s' %(config_inline.SWITCH_INTERFACE_AF, config_inline.SWITCH_INTERFACE_HA_AF, config_inline.SWITCH_INTERFACE_A),
          'priority': config_common.PRIORITY_STATIC_PORT_BINDING_FLOW,
          'persistent': True,
          'hardTimeout': 0,
          'idleTimeout': 0,
          'match': {'inInterfaces': [intfAF, intfHA_AF]},
          'action':{'outInterfaces': [intfA]}}
         ]},

    {'test_name': 'pan_inline_mode_deny_msg',
     'input_syslog_msg': '<14>Aug 10 11:47:28 bizdev-pan-5050  : 1,2019/08/10 11:47:27,0009C101677,TRAFFIC,drop,1,2015/08/10 11:47:27,%s,%s,0.0.0.0,0.0.0.0,Dev_inline_drop,,,ping,vsys1,untrust3,trust3,ethernet1/10,,Dev_DirectFlow_Assist,2015/08/10 11:47:27,0,6,0,0,0,0,0x100000,icmp,deny,588,588,0,6,2015/08/10 11:47:12,0,any,0,8140342,0x0,10.0.0.0-10.255.255.255,172.16.0.0-172.31.255.255,0,6,0,policy-deny,0,0,0,0,,bizdev-pan-5050,from-policy' % (IP1, IP2),
     'num_entries': 3,
     'get_flows': 'DROP.*',
     'output_directflow_entries': [
         {'flow_name_regex': 'DROP_ping_ICMP_*?',
          'persistent': False,
          'priority': config_common.PRIORITY_DROP_FLOW,
          'hardTimeout': config_common.DROP_FLOW_LIFETIME * 60,
          'idleTimeout': config_common.DROP_FLOW_IDLE_TIMEOUT * 60,
          'match': {'ipProto': ICMP,  # icmp
                    'inInterfaces': [],
                    'ipSrc': {'mask': '255.255.255.255', 'ip': IP1},
                    'ipDst': {'mask': '255.255.255.255', 'ip': IP2}
                    },
          'action': {'outputDrop': True,}}
         ]
    }
]
