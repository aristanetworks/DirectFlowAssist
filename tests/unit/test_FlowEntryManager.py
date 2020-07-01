#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = line-too-long

import sys
# sys.path.extend(['../..','../../persist_common', '../../persist_pan'])

import unittest
import logging
import config
from mock import Mock, patch
from directflow_assist import FlowEntryManager


TCAM_STATS = {'num_avail': 1000,
              'num_used': 500,
              'pct_used': 50}

ACTIVE_FLOWS_1 = [
{   "priority": 40,
    "matchPackets": 20,
    "matchBytes": 0,
    "bridgeMacAddr": "00:1c:73:74:81:9e",
    "name": "BYPASS_FW_ping_ICMP_172-22-28-42_172-22-225-127_May26_11:19:20_RSP",
    "action": {
        "outputNormal": False,
        "outputLocal": False,
        "ipTos": 8,
        "loopback": False,
        "outInterfaces": [
            "Port-Channel10"
        ],
        "vlanPCP": 3,
        "egrMirrorInterfaces": [],
        "outputAll": False,
        "outputController": False,
        "outputDrop": False,
        "outputFlood": False,
        "ingrMirrorInterfaces": []
    },
    "hardTimeout": 600,
    "idleTimeout": 300,
    "persistent": False,
    "match": {
        "inInterfaces": [
            "Port-Channel20"
        ],
        "unknownL3V4MulticastAddress": False,
        "ethType": 2048,
        "ethTypeMask": 65535,
        "tcpSyn": False,
        "ipSrc": {
            "mask": "255.255.255.255",
            "ip": "172.22.28.42"
        },
        "tcpPsh": False,
        "tcpUrg": False,
        "tcpFin": False,
        "tcpRst": False,
        "ipProto": 1,
        "unknownL2V4MulticastAddress": False,
        "tcpAck": False,
        "ipDst": {
            "mask": "255.255.255.255",
            "ip": "172.22.225.127"
        }
    }
},
{
    "priority": 40,
    "matchPackets": 10,
    "matchBytes": 0,
    "bridgeMacAddr": "00:1c:73:74:81:9e",
    "name": "BYPASS_FW_ping_ICMP_172-22-225-127_172-22-28-42_May26_11:19:20_INI",
    "action": {
        "outputNormal": False,
        "outputLocal": False,
        "ipTos": 8,
        "loopback": False,
        "outInterfaces": [
            "Port-Channel20"
        ],
        "vlanPCP": 3,
        "egrMirrorInterfaces": [],
        "outputAll": False,
        "outputController": False,
        "outputDrop": False,
        "outputFlood": False,
        "ingrMirrorInterfaces": []
    },
    "hardTimeout": 600,
    "idleTimeout": 300,
    "persistent": False,
    "match": {
        "inInterfaces": [
            "Port-Channel10"
        ],
        "unknownL3V4MulticastAddress": False,
        "ethType": 2048,
        "ethTypeMask": 65535,
        "tcpSyn": False,
        "ipSrc": {
            "mask": "255.255.255.255",
            "ip": "172.22.225.127"
        },
        "tcpPsh": False,
        "tcpUrg": False,
        "tcpFin": False,
        "tcpRst": False,
        "ipProto": 1,
        "unknownL2V4MulticastAddress": False,
        "tcpAck": False,
        "ipDst": {
            "mask": "255.255.255.255",
            "ip": "172.22.28.42"
        }
    }
}]

ACTIVE_FLOWS_2 = [
{   "priority": 40,
    "matchPackets": 620,
    "matchBytes": 0,
    "bridgeMacAddr": "00:1c:73:74:81:9e",
    "name": "BYPASS_FW_ping_ICMP_172-22-28-42_172-22-225-127_May26_11:19:20_RSP",
    "action": {
        "outputNormal": False,
        "outputLocal": False,
        "ipTos": 8,
        "loopback": False,
        "outInterfaces": [
            "Port-Channel10"
        ],
        "vlanPCP": 3,
        "egrMirrorInterfaces": [],
        "outputAll": False,
        "outputController": False,
        "outputDrop": False,
        "outputFlood": False,
        "ingrMirrorInterfaces": []
    },
    "hardTimeout": 600,
    "idleTimeout": 300,
    "persistent": False,
    "match": {
        "inInterfaces": [
            "Port-Channel20"
        ],
        "unknownL3V4MulticastAddress": False,
        "ethType": 2048,
        "ethTypeMask": 65535,
        "tcpSyn": False,
        "ipSrc": {
            "mask": "255.255.255.255",
            "ip": "172.22.28.42"
        },
        "tcpPsh": False,
        "tcpUrg": False,
        "tcpFin": False,
        "tcpRst": False,
        "ipProto": 1,
        "unknownL2V4MulticastAddress": False,
        "tcpAck": False,
        "ipDst": {
            "mask": "255.255.255.255",
            "ip": "172.22.225.127"
        }
    }
},
{
    "priority": 40,
    "matchPackets": 310,
    "matchBytes": 0,
    "bridgeMacAddr": "00:1c:73:74:81:9e",
    "name": "BYPASS_FW_ping_ICMP_172-22-225-127_172-22-28-42_May26_11:19:20_INI",
    "action": {
        "outputNormal": False,
        "outputLocal": False,
        "ipTos": 8,
        "loopback": False,
        "outInterfaces": [
            "Port-Channel20"
        ],
        "vlanPCP": 3,
        "egrMirrorInterfaces": [],
        "outputAll": False,
        "outputController": False,
        "outputDrop": False,
        "outputFlood": False,
        "ingrMirrorInterfaces": []
    },
    "hardTimeout": 600,
    "idleTimeout": 300,
    "persistent": False,
    "match": {
        "inInterfaces": [
            "Port-Channel10"
        ],
        "unknownL3V4MulticastAddress": False,
        "ethType": 2048,
        "ethTypeMask": 65535,
        "tcpSyn": False,
        "ipSrc": {
            "mask": "255.255.255.255",
            "ip": "172.22.225.127"
        },
        "tcpPsh": False,
        "tcpUrg": False,
        "tcpFin": False,
        "tcpRst": False,
        "ipProto": 1,
        "unknownL2V4MulticastAddress": False,
        "tcpAck": False,
        "ipDst": {
            "mask": "255.255.255.255",
            "ip": "172.22.28.42"
        }
    }
}]

ACTIVE_FLOWS_3 = [
    {"name": "BYPASS_FW_1_INI",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel10"]},
     "match": {"inInterfaces": ["Port-Channel20"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.1"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.2"}}},
    {"name": "BYPASS_FW_1_RSP",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel20"]},
     "match": {"inInterfaces": ["Port-Channel10"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.2"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.1"}}},

    {"name": "BYPASS_FW_2_INI",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel10"]},
     "match": {"inInterfaces": ["Port-Channel20"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.3"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.4"}}},
    {"name": "BYPASS_FW_2_RSP",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel20"]},
     "match": {"inInterfaces": ["Port-Channel10"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.4"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.3"}}},

    {"name": "BYPASS_FW_3_INI",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel10"]},
     "match": {"inInterfaces": ["Port-Channel20"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.5"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.6"}}},
    {"name": "BYPASS_FW_3_RSP",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel20"]},
     "match": {"inInterfaces": ["Port-Channel10"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.6"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.5"}}},

    {"name": "BYPASS_FW_4_INI",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel10"]},
     "match": {"inInterfaces": ["Port-Channel20"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.7"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.8"}}},
    {"name": "BYPASS_FW_4_RSP",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel20"]},
     "match": {"inInterfaces": ["Port-Channel10"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.8"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.7"}}},

    {"name": "BYPASS_FW_5_INI",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel10"]},
     "match": {"inInterfaces": ["Port-Channel20"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.9"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.10"}}},
    {"name": "BYPASS_FW_5_RSP",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel20"]},
     "match": {"inInterfaces": ["Port-Channel10"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.10"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.9"}}},
]

ACTIVE_FLOWS_4 = [
    {"name": "BYPASS_FW_1_INI",
     "priority": 40,
     "matchPackets": 6000,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel10"]},
     "match": {"inInterfaces": ["Port-Channel20"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.1"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.2"}}},
    {"name": "BYPASS_FW_1_RSP",
     "priority": 40,
     "matchPackets": 6000,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel20"]},
     "match": {"inInterfaces": ["Port-Channel10"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.2"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.1"}}},

    {"name": "BYPASS_FW_2_INI",
     "priority": 40,
     "matchPackets": 3000,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel10"]},
     "match": {"inInterfaces": ["Port-Channel20"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.3"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.4"}}},
    {"name": "BYPASS_FW_2_RSP",
     "priority": 40,
     "matchPackets": 3000,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel20"]},
     "match": {"inInterfaces": ["Port-Channel10"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.4"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.3"}}},

    {"name": "BYPASS_FW_3_INI",
     "priority": 40,
     "matchPackets": 600,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel10"]},
     "match": {"inInterfaces": ["Port-Channel20"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.5"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.6"}}},
    {"name": "BYPASS_FW_3_RSP",
     "priority": 40,
     "matchPackets": 600,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel20"]},
     "match": {"inInterfaces": ["Port-Channel10"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.6"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.5"}}},

    {"name": "BYPASS_FW_4_INI",
     "priority": 40,
     "matchPackets": 300,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel10"]},
     "match": {"inInterfaces": ["Port-Channel20"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.7"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.8"}}},
    {"name": "BYPASS_FW_4_RSP",
     "priority": 40,
     "matchPackets": 300,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel20"]},
     "match": {"inInterfaces": ["Port-Channel10"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.8"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.7"}}},

    {"name": "BYPASS_FW_5_INI",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel10"]},
     "match": {"inInterfaces": ["Port-Channel20"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.9"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.10"}}},
    {"name": "BYPASS_FW_5_RSP",
     "priority": 40,
     "matchPackets": 0,
     "hardTimeout": 600,
     "idleTimeout": 300,
     "persistent": False,
     "action": {"outInterfaces": ["Port-Channel20"]},
     "match": {"inInterfaces": ["Port-Channel10"],
               "ipSrc": {"mask": "255.255.255.255", "ip": "1.1.1.10"},
               "ipProto": 6,
               "ipDst": {"mask": "255.255.255.255", "ip": "1.1.1.9"}}},
]

DBG1= False


class TestFlowEntryManager(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_update_flow_rates_cache_and_rate_calcs(self):
        fem = FlowEntryManager.FlowEntryMgr()
        fem.directflow_switch.get_active_flows = Mock(return_value=ACTIVE_FLOWS_1)
        fem.update_flow_rates_cache()
        fem.directflow_switch.get_active_flows.assert_called_with()
        key = 'ICMP_172.22.225.127:_172.22.28.42:'
        self.assertTrue(key in fem.flow_rates_cache)
        cache_entry = fem.flow_rates_cache[key]
        self.assertTrue(cache_entry.is_current)
        self.assertTrue(cache_entry.is_bypass)
        self.assertEqual(cache_entry.rate, -1)
        flow_ini_key = 'BYPASS_FW_ping_ICMP_172-22-225-127_172-22-28-42_May26_11:19:20_INI'
        flow_rsp_key = 'BYPASS_FW_ping_ICMP_172-22-28-42_172-22-225-127_May26_11:19:20_RSP'
        self.assertTrue(flow_ini_key in cache_entry.flows)
        self.assertTrue(flow_rsp_key in cache_entry.flows)
        fem.directflow_switch.get_active_flows = Mock(return_value=ACTIVE_FLOWS_2)
        fem.update_flow_rates_cache()
        self.assertEqual(cache_entry.rate, 7)

    def test_reap_least_active_flows(self):
        fem = FlowEntryManager.FlowEntryMgr()
        fem.directflow_switch.get_active_flows = Mock(return_value=ACTIVE_FLOWS_3)
        fem.update_flow_rates_cache()
        if DBG1:
            for k,v in fem.flow_rates_cache.items():
               print 'A***flow_rates_cache: %s  %s' % (k,v)
        config.TCAM_REAP_THRESHOLD_PCT = 50
        config.TCAM_REAP_LEAST_ACTIVE_PCT = 40
        tcam_stats = {'num_avail': 20, 'num_used': 10, 'pct_used': 50}
        fem.directflow_switch.tcam_directflow_utilization = Mock(return_value=tcam_stats)
        fem.directflow_switch.get_active_flows = Mock(return_value=ACTIVE_FLOWS_4)
        fem.directflow_switch.delete_flows = Mock()
        fem.reap_least_active_flows(tcam_stats)
        if DBG1:
            print ('TCAM_REAP_THRESHOaLD_PCT: %d, TCAM_REAP_LEAST_ACTIVE_PCT: %d'
                  %(config.TCAM_REAP_THRESHOLD_PCT, config.TCAM_REAP_LEAST_ACTIVE_PCT))
            for k,v in fem.flow_rates_cache.items():
                print 'B***flow_rates_cache: %s  %s' % (k,v)
            # self.assertTrue(False)  # force buffer dump (unittest -b option)
        least_active = ['BYPASS_FW_5_INI', 'BYPASS_FW_5_RSP', 
                        'BYPASS_FW_4_INI', 'BYPASS_FW_4_RSP']
        fem.directflow_switch.delete_flows.assert_called_with(least_active)


if __name__ == '__main__':
    unittest.main()
