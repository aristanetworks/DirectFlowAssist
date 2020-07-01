import os
import sys

path = os.path.dirname(os.path.realpath(__file__))
pythonpath = path.rpartition('/')[0]
sys.path.append(pythonpath)

import config_common 
import pan.config_shunt as config_shunt 

SYSLOG_TO_FLOWS_LATENCY = 3
NUM_STATIC_FLOWS = 4

IP1 = '1.1.1.1'
IP2 =  '2.2.2.2'
TCP = 6
UDP = 17
IP_PORT_SRC = 100
IP_PORT_DST = 200
timeout = '10m'
intfA = config_shunt.SWITCH_INTERFACE_A
if intfA.startswith('e'): intfA = 'Ethernet' + intfA[-1]
intfAF = config_shunt.SWITCH_INTERFACE_AF
if intfAF.startswith('e'): intfAF = 'Ethernet' + intfAF[-1]
intfHA_AF = config_shunt.SWITCH_INTERFACE_HA_AF
if intfHA_AF.startswith('e'): intfHA_AF = 'Ethernet' + intfHA_AF[-1]
intfB = config_shunt.SWITCH_INTERFACE_B
if intfB.startswith('e'): intfB = 'Ethernet' + intfB[-1]
intfBF = config_shunt.SWITCH_INTERFACE_BF
if intfBF.startswith('e'): intfBF = 'Ethernet' + intfBF[-1]
intfHA_BF = config_shunt.SWITCH_INTERFACE_HA_BF
if intfHA_BF.startswith('e'): intfHA_BF = 'Ethernet' + intfHA_BF[-1]


tests = [ {
      'test_name': 'pan_shunt_mode_static_flow',
      'input_syslog_msg': '',
      'num_entries': 4,
      'get_flows': 'STATIC.*',
      'output_directflow_entries': [ {
         'flow_name_regex': 'STATIC_THRU_FIREWALL__in:%s__out:%s_%s' %(config_shunt.SWITCH_INTERFACE_A, config_shunt.SWITCH_INTERFACE_AF, config_shunt.SWITCH_INTERFACE_HA_AF),
         'persistent': True,
         'priority': config_common.PRIORITY_STATIC_PORT_BINDING_FLOW,
         'hardTimeout': 0,
         'idleTimeout': 0,
         'match': {
                'inInterfaces': [intfA],
                }, 
         'action':{
             'outInterfaces': [intfAF, intfHA_AF],
            }},

            {
         'flow_name_regex': 'STATIC_THRU_FIREWALL__in:%s_%s__out:%s' %(config_shunt.SWITCH_INTERFACE_AF, config_shunt.SWITCH_INTERFACE_HA_AF, config_shunt.SWITCH_INTERFACE_A),
         'persistent': True,
         'priority': config_common.PRIORITY_STATIC_PORT_BINDING_FLOW,
         'hardTimeout': 0,
         'idleTimeout': 0,
         'match': {
                'inInterfaces': [intfAF, intfHA_AF],
                }, 
         'action':{
             'outInterfaces': [intfA],
            }},

           {
         'flow_name_regex': 'STATIC_THRU_FIREWALL__in:%s__out:%s_%s' %(config_shunt.SWITCH_INTERFACE_B, config_shunt.SWITCH_INTERFACE_BF, config_shunt.SWITCH_INTERFACE_HA_BF),
         'persistent': True,
         'priority': config_common.PRIORITY_STATIC_PORT_BINDING_FLOW,
         'hardTimeout': 0,
         'idleTimeout': 0,
         'match': {
                'inInterfaces': [intfB],
                }, 
         'action':{
             'outInterfaces': [intfBF, intfHA_BF],
            }},

            {
         'flow_name_regex': 'STATIC_THRU_FIREWALL__in:%s_%s__out:%s' %(config_shunt.SWITCH_INTERFACE_BF, config_shunt.SWITCH_INTERFACE_HA_BF, config_shunt.SWITCH_INTERFACE_B),
         'persistent': True,
         'priority': config_common.PRIORITY_STATIC_PORT_BINDING_FLOW,
         'hardTimeout': 0,
         'idleTimeout': 0,
         'match': {
                'inInterfaces': [intfBF, intfHA_BF],
                }, 
         'action':{
             'outInterfaces': [intfB],
            }},
]
},                                  
         
    {'test_name': 'pan_shunt_mode_allow_msg',
     'input_syslog_msg': '<14>May 29 14:10:11 PA-3020A.arista.com  : 1,2019/09/29 14:10:10,001801014991,TRAFFIC,start,1,2015/05/29 14:10:10,%s,%s,0.0.0.0,0.0.0.0,backup_flow_bypass,,,web-browsing,vsys1,untrust,trust,%s,%s,DirectFlow_Assist,2015/05/29 14:10:10,59169,1,%s,%s,0,0,0x0,tcp,allow,377,299,78,4,2015/05/29 14:10:02,0,any,0,2255104,0x0,10.0.0.0-10.255.255.255,172.16.0.0-172.31.255.255,0,3,1,n/a' %(IP1, IP2, config_shunt.FIREWALL_INTERFACE_AF, config_shunt.FIREWALL_INTERFACE_BF, IP_PORT_SRC, IP_PORT_DST),
     'num_entries': 6,
     'get_flows': 'BYPASS.*', 
     'output_directflow_entries': [
         {'flow_name_regex': 'BYPASS_FW_.*_INI',
          'persistent': False,
          'priority': config_common.PRIORITY_BYPASS_FW_FLOW, 
          'hardTimeout': config_common.BYPASS_FLOW_LIFETIME * 60,
          'idleTimeout': config_common.BYPASS_FLOW_IDLE_TIMEOUT * 60,
          'match': {'inInterfaces': [intfA],
                    'ipSrc': {'mask': '255.255.255.255', 'ip': IP1},
                    'ipDst': {'mask': '255.255.255.255', 'ip': IP2},
                    'ipProto': TCP,
                    'ipPortSrc': IP_PORT_SRC,
                    'ipPortDst': IP_PORT_DST},
          'action': {'outInterfaces': [intfB],
                     'outputDrop': False,
                     'vlanPCP': config_shunt.COS_TOS_MARKING['web-browsing']['COS'],
                     'ipTos': config_shunt.COS_TOS_MARKING['web-browsing']['TOS']}},
         {'flow_name_regex': 'BYPASS_FW_.*_RSP',
          'persistent': False,
          'priority': config_common.PRIORITY_BYPASS_FW_FLOW,  # SUGETHA: check type from test data and verify same in json from EOS
          'hardTimeout': config_common.BYPASS_FLOW_LIFETIME * 60,
          'idleTimeout': config_common.BYPASS_FLOW_IDLE_TIMEOUT * 60,
          'match': {'inInterfaces': [intfB],
                    'ipSrc': {'mask': '255.255.255.255', 'ip': IP2},
                    'ipDst': {'mask': '255.255.255.255', 'ip': IP1},
                    'ipProto': TCP,
                    'ipPortSrc': IP_PORT_DST,
                    'ipPortDst': IP_PORT_SRC},
          'action': {'outInterfaces': [intfA],
                     'outputDrop': False,
                     'vlanPCP': config_shunt.COS_TOS_MARKING['web-browsing']['COS'],
                     'ipTos': config_shunt.COS_TOS_MARKING['web-browsing']['TOS']}},
         ]
     },

    {'test_name': 'pan_shunt_mode_old_msg',
     'input_syslog_msg': '<14>May 29 14:10:11 PA-3020A.arista.com  : 1,2014/09/29 14:10:10,001801014991,TRAFFIC,start,1,2015/05/29 14:10:10,%s,%s,0.0.0.0,0.0.0.0,backup_flow_bypass,,,web-browsing,vsys1,untrust,trust,%s,%s,DirectFlow_Assist,2015/05/29 14:10:10,59169,1,%s,%s,0,0,0x0,tcp,allow,377,299,78,4,2015/05/29 14:10:02,0,any,0,2255104,0x0,10.0.0.0-10.255.255.255,172.16.0.0-172.31.255.255,0,3,1,n/a' %(IP1, IP2, config_shunt.FIREWALL_INTERFACE_AF, config_shunt.FIREWALL_INTERFACE_BF, IP_PORT_SRC, IP_PORT_DST),
     'num_entries': 4,
     'get_flows': '!STATIC.*|!BYPASS.*|!DENY.*',
     'output_directflow_entries': []
     },

     {'test_name': 'pan_shunt_mode_deny_msg',
     'input_syslog_msg': '<10>May 29 14:08:51 PA-3020A.arista.com  : 1,2019/05/29 14:08:50,001801014991,THREAT,flood,1,2015/05/29 14:08:50,%s,%s,0.0.0.0,0.0.0.0,Attack_on_linux4,,,not-applicable,vsys1,,,,,DirectFlow_Assist,2015/05/29 14:08:50,0,2,0,0,0,0,0x0,hopopt,drop,"",Session Limit Event(8801),any,critical,client-to-server,7069,0x0,10.0.0.0-10.255.255.255,172.16.0.0-172.31.255.255,0,,0,,,0,,,,,,,,0' %(IP1, IP2),
     'num_entries': 5,
     'get_flows': 'DROP.*',
     'output_directflow_entries': [
         {'flow_name_regex': 'DROP_Session_L_HOPOPT_*?',
          'persistent': False,
          'priority': config_common.PRIORITY_DROP_FLOW,
          'hardTimeout': config_common.DROP_FLOW_LIFETIME * 60,
          'idleTimeout': config_common.DROP_FLOW_IDLE_TIMEOUT * 60,
          'match': {
                    'inInterfaces': [],
                    'ipSrc': {'mask': '255.255.255.255', 'ip': IP1},
                    'ipDst': {'mask': '255.255.255.255', 'ip': IP2}},
          'action': {
                     'outputDrop': True,}}]
     }
]
