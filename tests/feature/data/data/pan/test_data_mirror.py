import os
import sys

path = os.path.dirname(os.path.realpath(__file__))
pythonpath = path.rpartition('/')[0]
sys.path.append(pythonpath)

import config_common 
import pan.config_mirror as config_mirror 

SYSLOG_TO_FLOWS_LATENCY = 3
NUM_STATIC_FLOWS = 1

IP1 = '1.1.1.1'
IP2 =  '2.2.2.2'
TCP = 6
UDP = 17
ICMP = 1 
IP_PORT_SRC = 100
IP_PORT_DST = 200
timeout = '10m'

tests = [
    {'test_name': 'pan_mirror_mode_setup_mirroring_flow',
     'input_syslog_msg': '',
     'num_entries': NUM_STATIC_FLOWS,
     'get_flows': 'MIRROR.*',
     'output_directflow_entries': [
         {'flow_name_regex': 'MIRROR_TO_FW_TAP_*?',
          'persistent': True,
          'priority': config_common.PRIORITY_STATIC_PORT_BINDING_FLOW,
          'hardTimeout': 0,
          'idleTimeout': 0,
          'match': {'inInterfaces': config_mirror.SWITCH_INTERFACES_TO_BE_MIRRORED},
          'action': {'outputNormal': True,
                     'egrMirrorInterfaces': config_mirror.SWITCH_INTERFACES_TO_FW_TAP}}]
     },

    {'test_name': 'pan_mirror_mode_deny_msg',
     'input_syslog_msg': '<14>Aug 10 11:47:28 bizdev-pan-5050  : 1,2019/08/10 11:47:27,0009C101677,TRAFFIC,drop,1,2015/08/10 11:47:27,%s,%s,0.0.0.0,0.0.0.0,Dev_inline_drop,,,ping,vsys1,untrust3,trust3,ethernet1/10,,Dev_DirectFlow_Assist,2015/08/10 11:47:27,0,6,0,0,0,0,0x100000,icmp,deny,588,588,0,6,2015/08/10 11:47:12,0,any,0,8140342,0x0,10.0.0.0-10.255.255.255,172.16.0.0-172.31.255.255,0,6,0,policy-deny,0,0,0,0,,bizdev-pan-5050,from-policy' % (IP1, IP2),
     'num_entries': 2,
     'get_flows': 'DROP.*',
     'output_directflow_entries': [
         {'flow_name_regex': 'DROP_ping_ICMP_*?',
          'persistent': False,
          'priority': config_common.PRIORITY_DROP_FLOW,
          'hardTimeout': config_common.DROP_FLOW_LIFETIME * 60,
          'idleTimeout': config_common.DROP_FLOW_IDLE_TIMEOUT * 60,
          'match': {'ipProto': ICMP, 
                    'inInterfaces': [],
                    'ipSrc': {'mask': '255.255.255.255', 'ip': IP1},
                    'ipDst': {'mask': '255.255.255.255', 'ip': IP2}
                    },
          'action': {'outputDrop': True,}}]
    }
]
