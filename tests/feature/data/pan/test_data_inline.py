
SYSLOG_TO_FLOWS_LATENCY = 3
NUM_STATIC_FLOWS = 2

IP1 = '1.1.1.1'
IP2 = '2.2.2.2'

tests = [
    {'test_name': 'pan_inline_mode_static_flow',
     'input_syslog_msg': '',
     'num_entries': NUM_STATIC_FLOWS,
     'get_flows': 'STATIC.*',
     'output_directflow_entries': [
         {'flow_name_regex': 'STATIC_TO_FIREWALL__in:%s__out:%s_%' %(config.SWITCH_INTERFACE_A, config.SWITCH_INTERFACE_AF, config.SWITCH_INTERFACE_HA_AF),
          'priority': config.PRIORITY_STATIC_PORT_BINDING_FLOW,
          'persistent': True,
          'hardTimeout': 0,
          'idleTimeout': 0,
          'match': {'inInterfaces': [config.SWITCH_INTERFACE_A]},
          'action':{'outInterfaces': [config.SWITCH_INTERFACE_AF, config.SWITCH_INTERFACE_HA_AF]}},
         
         {'flow_name_regex': 'STATIC_TO_FIREWALL__in:%s_%__out:%s' %(config.SWITCH_INTERFACE_AF, config.SWITCH_INTERFACE_HA_AF, config.SWITCH_INTERFACE_A),
          'priority': config.PRIORITY_STATIC_PORT_BINDING_FLOW,
          'persistent': True,
          'hardTimeout': 0,
          'idleTimeout': 0,
          'match': {'inInterfaces': [config.SWITCH_INTERFACE_AF, config.SWITCH_INTERFACE_HA_AF]},
          'action':{'outInterfaces': [config.SWITCH_INTERFACE_A]}}
         ]},

    {'test_name': 'pan_inline_mode_deny_msg',
     'input_syslog_msg': '<14>Aug 10 11:47:28 bizdev-pan-5050  : 1,2019/08/10 11:47:27,0009C101677,TRAFFIC,drop,1,2015/08/10 11:47:27,%s,%s,0.0.0.0,0.0.0.0,Dev_inline_drop,,,ping,vsys1,untrust3,trust3,ethernet1/10,,Dev_DirectFlow_Assist,2015/08/10 11:47:27,0,6,0,0,0,0,0x100000,icmp,deny,588,588,0,6,2015/08/10 11:47:12,0,any,0,8140342,0x0,10.0.0.0-10.255.255.255,172.16.0.0-172.31.255.255,0,6,0,policy-deny,0,0,0,0,,bizdev-pan-5050,from-policy' % (IP1, IP2),
     'output_directflow_entries': [
         {'flow_name_regex': 'DROP_ping_ICMP_*?',
          'persistent': False,
          'priority': PRIORITY_DROP_FLOW,
          'hardTimeout': DROP_FLOW_LIFETIME * 60,
          'idleTimeout': DROP_FLOW_IDLE_TIMEOUT * 60,
          'match': {'ipProto': 1,  # icmp
                    'ipSrc': {'ip': IP1},
                    'ipDst': {'ip': IP2}
                    },
          'action': {'outputDrop': True,}}
         ]
    }
]
