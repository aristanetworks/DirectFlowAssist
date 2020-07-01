#!/usr/bin/env python2.7
#
# Copyright (c) 2014-2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = broad-except

''' Manages Directflow entries in TCAM, Sysdb and running-config
'''

import time
import logging
import threading
import config
from directflow_assist.common import utils
from .DirectFlowSwitch import (get_directflow_switch, is_dfa_dynamic_flow,
                               is_dfa_static_flow)

MIN_FLOWMGR_RUN_INTERVAL = 30
FLOWMGR_ERROR_RETRIES = 5


class FlowEntryMgr(threading.Thread):
    ''' handles removal of inactive flow entries in sysDB and running
        config and reaping of least active flows in TCAM when above
        configured threshold
    '''
    def __init__(self):
        super(FlowEntryMgr, self).__init__()
        self.name = 'FlowEntryMgr_thread'
        self.keep_running = True
        self.directflow_switch = get_directflow_switch()
        self.flow_rates_cache = {}  # key= flow name, val= rate_cache_entry
        if config.FLOWMGR_RUN_INTERVAL >= MIN_FLOWMGR_RUN_INTERVAL:
            self.run_interval = config.FLOWMGR_RUN_INTERVAL
        else:
            self.run_interval = MIN_FLOWMGR_RUN_INTERVAL
            logging.warn('FLOWMGR_RUN_INTERVAL less than minimum, using %ds',
                         self.run_interval)

    def run(self):
        ''' thread entry point
        '''
        if config.TCAM_REAP_LEAST_ACTIVE_PCT > 0:
            reap = True
        else:
            logging.info('%s reap least active flows DISABLED', self.name)
            reap = False
        logging.info('starting %s, run interval: %ds', self.name, self.run_interval)
        num_errors = 0
        while self.keep_running:   # main loop
            try:
                tcam_stats = self.directflow_switch.tcam_directflow_utilization()
                if tcam_stats:
                    logging.debug('FlowEntryMgr doing cleanup and checking TCAM avail'
                                  ' %s, used %s, pct %s%%', tcam_stats['num_avail'],
                                  tcam_stats['num_used'], tcam_stats['pct_used'])
                self.directflow_switch.delete_inactive_flows()
                if reap:
                    self.reap_least_active_flows(tcam_stats)  # and check for asym flows
                time.sleep(self.run_interval)
            except Exception as exc:
                logging.exception('FlowEntryMgr: %s', exc)
                num_errors += 1
                if num_errors <= FLOWMGR_ERROR_RETRIES:
                    logging.info('FlowEntryMgr continuing, retry: %s/%s',
                                 num_errors, FLOWMGR_ERROR_RETRIES)
                else:
                    break
        logging.info('FlowEntryMgr %s exiting', self.name)

    def stop_running(self):
        ''' clear flag
        '''
        self.keep_running = False

    def reap_least_active_flows(self, tcam_stats):
        ''' preserve TCAM entries for most active flows by deleting
            least active flows
        '''
        # logging.debug('FlowEntryMgr reap_least_active_flows running')
        self.update_flow_rates_cache()
        if tcam_stats and tcam_stats['pct_used'] >= config.TCAM_REAP_THRESHOLD_PCT:
            logging.debug('TCAM util %d%% is at or above reap threshold %d%%',
                          tcam_stats['pct_used'], config.TCAM_REAP_THRESHOLD_PCT)
            num_flows_to_reap = int(config.TCAM_REAP_LEAST_ACTIVE_PCT / float(100) *
                                    tcam_stats['num_used'])
            logging.debug('# flows to be reaped: %d', num_flows_to_reap)
            if num_flows_to_reap == 0:
                return
            remove_flows = []
            for flow_name in self.least_active_flownames(num_flows_to_reap):
                logging.debug('reaping flow: %s', flow_name)
                remove_flows.append(flow_name)
            if remove_flows:
                self.directflow_switch.delete_flows(remove_flows)
                logging.info('Removed %d least active flows from switch',
                             len(remove_flows))

    def least_active_flownames(self, num_flows):
        ''' returns list of least active flow names in flow rates cache
        '''
        # eliminate initial entries with rate = -1
        cache_entries = [e for e in self.flow_rates_cache.values()
                         if e.rate >= 0]
        if not cache_entries:
            logging.debug('least_active_flownames: all cached flows have rate -1')
        cache_entries.sort(key=lambda entry: entry.rate)     # sort by rate
        # logging.debug('sorted flow_rates_cache:\n%s', utils.dump_list(cache_entries))
        flow_names = []
        for entry in cache_entries:
            flow_names.extend(entry.get_flow_names())
            if len(flow_names) >= num_flows:
                break
        return flow_names

    def update_flow_rates_cache(self):
        ''' maintains flow_rates_cache
            also detects missing static binding flow entries
        '''
        static_flow_count = 0
        start_cache_len = len(self.flow_rates_cache)
        # logging.debug('cache PRE update: %s', self.dump_cache())
        self.reset_cache_current_flags()     # prep for stale entry cleanup
        for flow in self.directflow_switch.get_active_flows():
            flow_name = flow['name']
            if is_dfa_dynamic_flow(flow_name):
                key = compute_cache_key(flow)
                # logging.debug('cache key: %s for flow: %s', key, flow_name)
                if key in self.flow_rates_cache:
                    self.flow_rates_cache[key].update(flow, self.run_interval)
                else:
                    self.flow_rates_cache[key] = RateCacheEntry(flow)
            elif is_dfa_static_flow(flow_name):
                static_flow_count += 1
        if ((config.OPERATING_MODE == config.SHUNT_MODE or
             config.OPERATING_MODE == config.MIRROR_AND_SHUNT_MODE) and
                static_flow_count != 4):
            logging.warning('DFA static binding flow count != 4, check setup')
        elif config.OPERATING_MODE == config.INLINE_MODE and static_flow_count != 2:
            logging.warning('DFA static binding flow count != 2, check setup')
        self.remove_stale_cache_entries()
        if not config.ALLOW_ASYMMETRIC_BYPASSES:
            self.delete_asymmetric_flow_entries()
        if start_cache_len or self.flow_rates_cache:
            logging.debug('FlowEntryMgr update_flow_rates_cache size pre: %d, post: %d',
                          start_cache_len, len(self.flow_rates_cache))
            # if self.flow_rates_cache:
            #    logging.debug('flow_rates_cache POST update:\n%s', self.dump_cache())

    def delete_asymmetric_flow_entries(self):
        ''' detect and delete bypass or redirect to firewall flow entries
            that are not paired for a bi-directionalconnection
        '''
        logging.debug('FlowEntryMgr checking for asymmetric flow entries')
        asym_flows_to_be_removed = []
        for cache_entry in self.flow_rates_cache.values():
            # redirect and some bypass flows use INI-RSP, INI2-RSP2 flow pairs
            if ((cache_entry.is_bypass or cache_entry.is_redirect) and
                    (len(cache_entry.flows) != 2 and len(cache_entry.flows) != 4)):
                if cache_entry.has_asymmetric_flows:
                    logging.warning('asymmetric flow entry confirmed on 2nd pass: %s',
                                    cache_entry)
                    asym_flows_to_be_removed.extend(cache_entry.get_flow_names())
                else:
                    cache_entry.has_asymmetric_flows = True
                    logging.debug('potential asymmetric flow cache entry detected: %s',
                                  cache_entry)
        if asym_flows_to_be_removed:
            logging.info('removing asymmetric flows: %s', asym_flows_to_be_removed)
            self.directflow_switch.delete_flows(asym_flows_to_be_removed)

    def reset_cache_current_flags(self):
        ''' clear current flags on cache entries in preparation for stale
            entry cldeanup at end of update run
        '''
        for cache_entry in self.flow_rates_cache.values():
            cache_entry.reset_current_flags()

    def remove_stale_cache_entries(self):
        ''' removes stale flow rates cache entries
        '''
        for key in self.flow_rates_cache.keys():
            if not self.flow_rates_cache[key].is_current:
                del self.flow_rates_cache[key]
                # logging.debug('purge stale from flow_rates_cache: %s', key)
            else:
                self.flow_rates_cache[key].remove_stale_flows()

    def dump_cache(self):
        ''' returns string output of the flow rates cache
        '''
        out = ''
        for key, entry in self.flow_rates_cache.items():
            if out:  # skip first
                out += '\n'
            if entry.is_bypass or entry.is_redirect:
                out += 'key: %s, rate: %s, current: %s, asymm: %s' % (
                    key, entry.rate, entry.is_current, entry.has_asymmetric_flows)
                for name, stats in entry.flows.items():
                    out += ('\n  %s, rate: %s, pkts: %s' % (name, stats['rate'],
                                                            stats['pkts']))
            else:  # drop flow
                out += 'key: %s, rate: %s, pkts: %s, current: %s' % (
                    key, entry.rate, entry.flows.values()[0]['pkts'],
                    entry.is_current)
        return out


def compute_cache_key(flow):
    ''' Computes key for flow rate cache.
        computes a  normalized pairing key for bypass flows
        endswith RSP key = ipDst+ipPortDst+ipSrc+ipPortSrc+ipProto
        Maint. Note: verify flow suffixes in sync with FlowAssistController
    '''
    flow_name = flow['name']
    if flow_name.startswith(config.DROP_FLOWNAME_PREFIX):
        return flow['name']   # for drops just use flow name
    else:
        try:
            protocol_num = str(flow['match']['ipProto'])
            protocol = utils.IP_PROTOCOL.get(protocol_num, protocol_num)
            src_ip = flow['match']['ipSrc']['ip']
            dst_ip = flow['match']['ipDst']['ip']
            src_port = flow['match'].get('ipPortSrc', '')
            dst_port = flow['match'].get('ipPortDst', '')
            vlan = ''
            if 'vlan' in flow['match']:
                vlan = '_VL%s' % flow['match']['vlan']

            if flow_name.endswith('INI') or flow_name.endswith('INI2'):
                key = ('%s_%s:%s_%s:%s%s' %
                       (protocol, src_ip, src_port, dst_ip, dst_port, vlan))
            elif flow_name.endswith('RSP') or flow_name.endswith('RSP2'):
                # flip src & dst for key
                key = ('%s_%s:%s_%s:%s%s' %
                       (protocol, dst_ip, dst_port, src_ip, src_port, vlan))
            else:
                logging.warn('unknown flow name suffix in RateCacheEntry: %s',
                             flow_name)
                key = ''
            return key
        except Exception as exc:
            logging.exception(exc)
            logging.debug('Exception debug: extract_bypass_flow_pair_keys flow:\n%s',
                          utils.unpack(flow))


# -----------------------------------------------------------------------------
class RateCacheEntry(object):
    ''' Entry for the flow rates cache
        For bypass and redirect to firewall flows we need to consider the
        average rate for the pair of flows used by a full-duplex connection
        when we check for least active flows before reaping.
    '''
    def __init__(self, flow):
        self.is_current = True
        self.is_bypass = flow['name'].startswith(config.BYPASS_FLOWNAME_PREFIX)
        self.is_redirect = flow['name'].startswith(config.REDIR_FLOWNAME_PREFIX)
        self.has_asymmetric_flows = False
        self.rate = -1      # for a bypass connection is average for both flows
        self.flows = {}
        self.insert_flow(flow)

    def insert_flow(self, flow):
        ''' insert a flow '''
        flow_name = flow['name']
        self.flows[flow_name] = {'rate': -1,
                                 'current': True,  # currently present in TCAM
                                 'pkts': flow['matchPackets']}

    def update(self, flow, run_interval):
        ''' for bypass connections rate is the average of both directional
            flows, i.e. the initiating ('INI') and response ('RSP') flows
        '''
        self.is_current = True
        flow_name = flow['name']
        if flow_name not in self.flows:
            self.insert_flow(flow)
            return

        # logging.debug('RCE updating stats for flow: %s', flow)
        self.flows[flow_name]['current'] = True
        new_match_pkts = int(flow['matchPackets'])
        prev_match_pkts = self.flows[flow_name]['pkts']
        flow_rate = ((new_match_pkts - prev_match_pkts) / run_interval)
        self.flows[flow_name]['pkts'] = new_match_pkts
        self.flows[flow_name]['rate'] = flow_rate
        self.compute_avg_rate()

    def compute_avg_rate(self):
        ''' compute average rate
        '''
        count = 0
        sum_rates = 0
        for flow_vals in self.flows.values():
            sum_rates += flow_vals['rate']
            count += 1
        self.rate = sum_rates / count

    def get_flow_names(self):
        ''' returns flow names '''
        return self.flows.keys()

    def reset_current_flags(self):
        ''' clear flags in prep for later stale entry check
        '''
        self.is_current = False
        for flow_vals in self.flows.values():
            flow_vals['current'] = False

    def remove_stale_flows(self):
        ''' removes stale flows
        '''
        for key in self.flows.keys():
            if not self.flows[key]['current']:
                # logging.debug('RCE: purging stale flow: %s', key)
                del self.flows[key]

    def __str__(self):
        flows_str = ''
        for name, stats in self.flows.items():
            if len(flows_str):
                flows_str += '\n'
            flows_str += ' %s, %s' % (name, stats)

        if self.is_bypass or self.is_redirect:
            return ('rate: %s, curr: %s, bypass: %s, redirect: %s, asym: %s, '
                    'flows:\n%s' %
                    (self.rate, self.is_current, self.is_bypass,
                     self.is_redirect, self.has_asymmetric_flows, flows_str))
        else:
            return ('rate: %s, curr: %s, %s' %
                    (self.rate, self.is_current, flows_str))

# def test1():
#     ''' unit test
#     '''
#     from .DirectFlowSwitch import DirectFlowSwitch
#     #inject_test_flows('bizdev-7050s', 1000, 'MAX_FLOWS_TEST')
#     dfsw = DirectFlowSwitch('bizdev-7050s', 'eapi', 'eapi', protocol='HTTPS')
#     #print '\nDirectFlow TCAM stats: %s' % dfsw.tcam_directflow_utilization()
#     dfsw.reap_least_active_flows()
#     inject_test_flows('bizdev-7050s', 500, 'DROP_TEST')
#     dfsw.reap_least_active_flows()


def test2():
    ''' unit test
    '''
    from .DirectFlowSwitch import DirectFlowSwitch
    # inject_test_flows('bizdev-7050s', 1000, 'MAX_FLOWS_TEST')
    dfsw = DirectFlowSwitch('bizdev-7050s', 'eapi', 'eapi', protocol='HTTPS')
    dfsw.delete_inactive_flows()


def test3():
    ''' unit test
    '''
    flow_entry_mgr = FlowEntryMgr()
    flow_entry_mgr.setDaemon(True)
    flow_entry_mgr.start()
    time.sleep(100)

if __name__ == "__main__":
    test3()
