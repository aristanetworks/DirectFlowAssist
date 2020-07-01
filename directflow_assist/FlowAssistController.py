#!/usr/bin/env python2.7
#
# Copyright (c) 2013-2015 Arista Networks, Inc.  All rights reserved
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = wildcard-import, unused-wildcard-import, broad-except
# pylint: disable = too-many-arguments, too-many-branches, too-many-instance-attributes

''' handles processing of syslog messages and flow entry management
'''

import logging
import re
from directflow_assist.common import utils
from .DedupCache import DeduplicationCache
from .DirectFlowSwitch import get_directflow_switch
import config

FW_SWITCH_INTF_MAP = {
    config.FIREWALL_INTERFACE_AF: [config.SWITCH_INTERFACE_A, config.SWITCH_INTERFACE_B],
    config.FIREWALL_INTERFACE_BF: [config.SWITCH_INTERFACE_B, config.SWITCH_INTERFACE_A]}


class FlowAssistController(object):
    ''' Extracts 5-tuple + FW interfaces + FW zones (e.g. trust, untrust)
        from syslog message to generate a flow specification
        Detects duplicate syslog msg (i.e. with same flow match criteria)
        so we don't configure a duplicate DirectFlow entry on switch.
        Note: can't simply use whole syslog msg string since they
        usually contain timestamps or sequence numbers that may be unique
    '''
    def __init__(self):
        self.dedup_cache = None
        self.flow_lifetime = None
        self.assist_action = None
        self.flow_match_criteria = None
        self.msg = None
        self.is_paused = False
        self.msg_class = config.get_msg_class()
        if config.DEDUP_CACHE_MAX_SIZE > 0:
            self.dedup_cache = DeduplicationCache(config.DEDUP_CACHE_MAX_SIZE,
                                                  config.DEDUP_CACHE_ENTRY_LIFETIME)
        self.directflow_switch = get_directflow_switch()

    def process_msg(self, raw_msg):
        ''' process valid syslog messages, ensure not duplicates, extract
            flow spec, install flow on a DirectFlow capable switch
        '''
        if self.is_paused:  # optional demo controller pauses/resumes
            logging.info('processing paused, ignoring syslog msg')
            return

        logging.info('raw syslog msg: %s', raw_msg)
        self.msg = self.msg_class(raw_msg)
        if not self.msg.is_valid():
            logging.info('ignoring, invalid msg or timestamp too old')
            return

        logging.debug('decoded syslog msg: \n%s', self.msg.decoded_msg())
        if not self.check_syslog_msg_triggers():
            logging.info('ignoring msg, no syslog msg triggers in config fired')
            return

        if self.assist_action == config.DFA_IGNORE:
            logging.info('ignoring msg, action= DFA_IGNORE')
            return

        if self.dedup_cache is not None:
            key = self.generate_dedup_key()
            if self.dedup_cache.contains_key(key):
                logging.info('ignoring syslog msg that would result in duplicate flow '
                             'entry, dedup interval: %d min.',
                             config.DEDUP_CACHE_ENTRY_LIFETIME)
                return
            else:
                self.dedup_cache.insert_key(key)
        flow_specs = self.generate_flow_specs()
        if flow_specs:
            self.directflow_switch.add_flows(flow_specs)

    def check_syslog_msg_triggers(self):
        ''' try each trigger in controller spec to see if any fire
            for this syslog msg
        '''
        try:
            # logging.debug('syslog msg_dict: %s', self.msg.msg_dict)
            for spec in config.DFA_CONTROLLER_SPEC:
                trigger = spec['trigger']
                self.assist_action = spec['action']
                if not trigger:  # skip empty triggers
                    continue
                if (self.assist_action == config.BYPASS_FIREWALL and
                        not config.OPERATING_MODE == config.SHUNT_MODE):
                    logging.debug('ignoring DFA_CONTROLLER_SPEC entry with action %s in'
                                  ' mode %s', self.assist_action, config.OPERATING_MODE)
                    continue
                # logging.debug('checking DFA_CONTROLLER_SPEC: TRIGGER=%s', trigger)
                if self.trigger_fired(trigger):
                    if self.assist_action == config.DFA_IGNORE:
                        self.flow_match_criteria = {}
                    else:
                        self.flow_match_criteria = spec['flow_match']
                    logging.info('syslog trigger firing, spec: TRIGGER=%s, ACTION=%s, '
                                 'MATCH=%s', trigger, self.assist_action,
                                 self.flow_match_criteria)
                    return True
            logging.debug('No triggers matched this sylog msg')
            return False
        except Exception as ex:
            logging.error('Exception in check_syslog_msg_triggers: %s', ex)
            return False

    def trigger_fired(self, trigger):
        ''' check each key, value_list in trigger
        '''
        if not trigger:  # skip empty triggers
            return False
        for field_name, field_values in trigger.items():
            if field_name not in self.msg.msg_dict:
                return False

            if isinstance(field_values, str):
                field_values = [field_values]

            found_value_in_msg = False
            msg_field = self.msg.msg_dict[field_name]
            for value_regex in field_values:
                if re.search(value_regex, msg_field, re.IGNORECASE):
                    found_value_in_msg = True
                    # logging.debug('syslog trigger key satisfied: field_name [%s] '
                    #          'value [%s] contains [%s]', field_name,
                    #          self.msg.msg_dict[field_name], value_regex)
                    break
            if not found_value_in_msg:
                return False
        return True

    def generate_dedup_key(self):
        ''' generate dedup cache key
        '''
        key = '%s%s_%s' % (
            self.assist_action,
            '_VL%s' % self.msg.in_vlan if self.msg.in_vlan else '',
            self.get_match_tuple())
        logging.debug('generated dedup key [%s]', key)
        return key

    def get_cos_tos_marking_actions(self, flow_label):
        ''' use DirectFlow actions to set/mark Ethernet CoS and/or IP ToS
            fields in bypassed flows
            RFE110798
        '''
        actions = []
        try:
            if self.msg.app in config.COS_TOS_MARKING:
                if 'COS' in config.COS_TOS_MARKING[self.msg.app]:
                    cos_value = config.COS_TOS_MARKING[self.msg.app]['COS']
                    actions.append('set cos %d' % cos_value)
                if 'TOS' in config.COS_TOS_MARKING[self.msg.app]:
                    tos_value = config.COS_TOS_MARKING[self.msg.app]['TOS']
                    actions.append('set ip tos %d' % tos_value)
                if not actions:
                    logging.warning('Found %s in config.COS_TOS_MARKING but no '
                                    'COS or TOS key/value mapping', self.msg.app)
                    return
                logging.debug('app %s in config.COS_TOS_MARKING, actions: %s, '
                              'flow: %s', self.msg.app, actions, flow_label)
        except Exception as ex:
            logging.error('Unable to process COS_TOS_MARKINGs: %s', ex)
        return actions

    def generate_flow_specs(self):
        ''' returns a list of one or more flow_specs; each flow_spec is a dict
        '''
        self.set_flow_lifetime()
        if self.assist_action == config.DROP_FLOW:
            return self.generate_drop_flow_spec()

        elif self.assist_action == config.BYPASS_FIREWALL:
            return self.generate_bypass_flow_specs()

        elif self.assist_action == config.REDIRECT_TO_FIREWALL:
            return self.gen_redirect_to_fw_flow_specs()

        else:
            logging.error('unknown assist_action=[%s]', self.assist_action)

    def generate_drop_flow_spec(self):
        ''' generate_drop_flow_spec
        '''
        match_tuple = self.get_match_tuple()
        name = self.gen_flow_name('DROP')
        flow_spec = {
            'name': name,
            'match': match_tuple,
            'action': ['drop'],
            'priority': config.PRIORITY_DROP_FLOW,
            'persistent': False,
            'idle_time': config.DROP_FLOW_IDLE_TIMEOUT * 60,
            'lifetime': self.flow_lifetime}
        return [flow_spec]

    def gen_bypass_flow(self, name, in_intf, out_intf, flip_src_dst):
        ''' gen bypass flow spec
        '''
        match_tuple = self.get_match_tuple(flip_src_dst)
        flow_spec = {
            'name': name,
            'priority': config.PRIORITY_BYPASS_FW_FLOW,
            'persistent': False,
            'idle_time': config.BYPASS_FLOW_IDLE_TIMEOUT * 60,
            'lifetime': self.flow_lifetime,
            'match': ['input interface %s' % in_intf],
            'action': ['output interface %s' % out_intf]}
        flow_spec['match'].extend(match_tuple)
        qos_markings = self.get_cos_tos_marking_actions(name[-3:])
        if qos_markings:
            flow_spec['action'].extend(qos_markings)
        if config.REWRITE_VLAN_ON_EGRESS:
            if (out_intf == config.SWITCH_INTERFACE_A and
                    config.SWITCH_INTERFACE_A_VLAN != 0):
                flow_spec['action'].append('set vlan %s'
                                           % config.SWITCH_INTERFACE_A_VLAN)
            elif (out_intf == config.SWITCH_INTERFACE_B and
                  config.SWITCH_INTERFACE_B_VLAN != 0):
                flow_spec['action'].append('set vlan %s' %
                                           config.SWITCH_INTERFACE_B_VLAN)
        return flow_spec

    def validate_fw_intf_mapping(self):
        ''' check mappings
        '''
        for intf in [self.msg.in_intf, self.msg.out_intf]:
            if intf not in FW_SWITCH_INTF_MAP:
                logging.warning('firewall intf [%s] from syslog msg not '
                                'defined in config.py', intf)
                return False
        return True

    def generate_bypass_flow_specs(self):
        ''' generate initiating and response flow specifications for a
            firewall bypass connection
        '''
        init_flow_name = self.gen_flow_name(prefix='BYPASS_FW', suffix='INI')

        # create bypass flow entry for response direction on this connection
        resp_flow_name = self.gen_flow_name(prefix='BYPASS_FW', suffix='RSP',
                                            flip_src_dst=True)
        flow_specs = []
        if config.FW_INTF_IN_SYSLOG_MSG:
            if not self.validate_fw_intf_mapping():
                return
            init_in_intf, init_out_intf = FW_SWITCH_INTF_MAP[self.msg.in_intf]
            resp_in_intf, resp_out_intf = FW_SWITCH_INTF_MAP[self.msg.out_intf]
            flow_specs.append(self.gen_bypass_flow(
                init_flow_name, init_in_intf, init_out_intf,
                flip_src_dst=False))
            flow_specs.append(self.gen_bypass_flow(
                resp_flow_name, resp_in_intf, resp_out_intf,
                flip_src_dst=True))
        else:
            # don't know direction thru firewall so setup flows for both
            # directions and use idle timeout to cleanup unused flow pair
            init_in_intf, init_out_intf = (
                config.SWITCH_INTERFACE_A, config.SWITCH_INTERFACE_B)
            resp_in_intf, resp_out_intf = (
                config.SWITCH_INTERFACE_B, config.SWITCH_INTERFACE_A)
            flow_specs.append(self.gen_bypass_flow(
                init_flow_name, config.SWITCH_INTERFACE_A, config.SWITCH_INTERFACE_B,
                flip_src_dst=False))
            flow_specs.append(self.gen_bypass_flow(
                resp_flow_name, config.SWITCH_INTERFACE_B, config.SWITCH_INTERFACE_A,
                flip_src_dst=True))
            # now swap flow directions thru switch
            flow_specs.append(self.gen_bypass_flow(
                init_flow_name + '2', config.SWITCH_INTERFACE_B,
                config.SWITCH_INTERFACE_A, flip_src_dst=False))
            flow_specs.append(self.gen_bypass_flow(
                resp_flow_name + '2', config.SWITCH_INTERFACE_A,
                config.SWITCH_INTERFACE_B, flip_src_dst=True))
        return flow_specs

    def gen_redirect_to_fw_flow_specs(self):
        ''' setup redirect thru FW flows
            since don't know direction of flow create entries for both
            directions, with a short idle timeout for cleanup
         '''
        fspec = self.generate_redirect_flows(config.SWITCH_INTERFACE_A,
                                             config.SWITCH_INTERFACE_AF,
                                             config.SWITCH_INTERFACE_B,
                                             config.SWITCH_INTERFACE_BF, 1)
        fspec.extend(self.generate_redirect_flows(config.SWITCH_INTERFACE_B,
                                                  config.SWITCH_INTERFACE_BF,
                                                  config.SWITCH_INTERFACE_A,
                                                  config.SWITCH_INTERFACE_AF, 2))
        return fspec

    def generate_redirect_flows(self, init_intf, init_fw_intf,
                                resp_intf, resp_fw_intf, set_name):
        ''' generate_redirect_flows
        '''
        time = utils.ts_date(with_year=False, ms_prec=0)
        name = ('REDIR_TO_FW_%s_%s_%s_%s__%s:%s_%sINI' %
                (time, self.msg.app_short, self.msg.protocol.upper(),
                 self.msg.src_ip, self.msg.dst_ip, self.msg.dst_port,
                 set_name))
        name = utils.scrub_flow_name(name)
        init_flow_spec = {
            'name': name,
            'match': self.get_match_tuple(),
            'action': ['output interface %s' % init_fw_intf],
            'priority': config.PRIORITY_REDIRECT_FLOW,
            'persistent': False,
            'lifetime': self.flow_lifetime,
            'idle_time': config.REDIRECT_FLOW_IDLE_TIMEOUT * 60}
        init_flow_spec['match'].append('input interface %s' % init_intf)

        # create bypass flow entry for server response on this socket
        name = ('REDIR_TO_FW_%s_%s_%s_%s:%s__%s_%sRSP' %
                (time, self.msg.app_short, self.msg.protocol.upper(),
                 self.msg.dst_ip, self.msg.dst_port, self.msg.src_ip,
                 set_name))
        name = utils.scrub_flow_name(name)
        resp_flow_spec = {
            'name': name,
            'match': self.get_match_tuple(flip_src_dst=True),
            'action': ['output interface %s' % resp_fw_intf],
            'persistent': False,
            'priority': config.PRIORITY_REDIRECT_FLOW,
            'lifetime': self.flow_lifetime,
            'idle_time': config.REDIRECT_FLOW_IDLE_TIMEOUT * 60}
        resp_flow_spec['match'].append('input interface %s' % resp_intf)
        return [init_flow_spec, resp_flow_spec]

    def gen_flow_name(self, prefix='', suffix='', flip_src_dst=False):
        ''' generate string used by DirectFlow for flow entry name
            dev note: logic below is very similar to get_match_tuple()
            consider combining methods in future refactoring
        '''
        time = utils.ts_date(with_year=False, ms_prec=0)
        name = '%s_%s' % (prefix, self.msg.app_short)
        if config.PROTOCOL in self.flow_match_criteria:
            name += '_%s' % self.msg.protocol.upper()

        src_ip_and_port = ''
        if (config.SRC_IP in self.flow_match_criteria and
                self.msg.src_ip != '0.0.0.0'):
            src_ip_and_port += '_%s' % self.msg.src_ip
        if (config.SRC_PORT in self.flow_match_criteria and
                self.msg.src_port != '0'):
            src_ip_and_port += ':%s' % self.msg.src_port

        dst_ip_and_port = ''
        if (config.DST_IP in self.flow_match_criteria and
                self.msg.dst_ip != '0.0.0.0'):
            dst_ip_and_port += '_%s' % self.msg.dst_ip
        if (config.DST_PORT in self.flow_match_criteria and
                self.msg.dst_port != '0'):
            dst_ip_and_port += ':%s' % self.msg.dst_port

        if not flip_src_dst:
            name += '%s%s' % (src_ip_and_port, dst_ip_and_port)
        else:
            name += '%s%s' % (dst_ip_and_port, src_ip_and_port)

        if self.msg.in_vlan:
            name += '_VL%s' % self.msg.in_vlan
        if self.msg.out_vlan:
            name += '_VL%s' % self.msg.out_vlan

        name += '_%s' % time
        if suffix:
            name += '_%s' % suffix
        name = utils.scrub_flow_name(name)
        return name

    def get_match_tuple(self, flip_src_dst=False):
        ''' get_match_tuple
        '''
        match = []
        if self.msg.in_vlan and self.msg.out_vlan:
            if not flip_src_dst:
                match.append('vlan %s' % self.msg.in_vlan)
            else:
                match.append('vlan %s' % self.msg.out_vlan)

        if config.SRC_IP in self.flow_match_criteria and self.msg.src_ip != '0.0.0.0':
            if not flip_src_dst:
                match.append('source ip %s' % self.msg.src_ip)
            else:
                match.append('destination ip %s' % self.msg.src_ip)

        if config.DST_IP in self.flow_match_criteria and self.msg.dst_ip != '0.0.0.0':
            if not flip_src_dst:
                match.append('destination ip %s' % self.msg.dst_ip)
            else:
                match.append('source ip %s' % self.msg.dst_ip)

        if (config.SRC_PORT in self.flow_match_criteria and
                self.msg.src_port != '0' and
                self.msg.protocol.upper() != 'ICMP' and
                self.msg.protocol.upper() != 'HOPOPT'):
            if not flip_src_dst:
                match.append('source port %s' % self.msg.src_port)
            else:
                match.append('destination port %s' % self.msg.src_port)

        if (config.DST_PORT in self.flow_match_criteria and
                self.msg.dst_port != '0' and
                self.msg.protocol.upper() != 'ICMP' and
                self.msg.protocol.upper() != 'HOPOPT'):
            if not flip_src_dst:
                match.append('destination port %s' % self.msg.dst_port)
            else:
                match.append('source port %s' % self.msg.dst_port)

        if (config.PROTOCOL in self.flow_match_criteria and
                self.msg.protocol.upper() != 'HOPOPT'):
            match.append('ip protocol %s' % self.msg.protocol)
        return match

    def set_flow_lifetime(self):
        ''' extract flow lifetime from firewall rule name or if not present
            use defaults from config file '''
        lifetime = 0
        if self.msg.rule_name:
            regex = r'.*_(\d{1,6})m$'
            mobj = re.match(regex, self.msg.rule_name, re.IGNORECASE)
            if mobj:
                lifetime = int(mobj.group(1))
                logging.debug('flow lifetime [%d] min. extracted from FW policy [%s]',
                              lifetime, self.msg.rule_name)
        if 1 <= lifetime <= config.FLOW_LIFETIME_MAX:
            self.flow_lifetime = lifetime * 60
        elif self.assist_action == config.DROP_FLOW:
            self.flow_lifetime = config.DROP_FLOW_LIFETIME * 60
        elif self.assist_action == config.BYPASS_FIREWALL:
            self.flow_lifetime = config.BYPASS_FLOW_LIFETIME * 60
        elif self.assist_action == config.REDIRECT_TO_FIREWALL:
            self.flow_lifetime = config.REDIRECT_FLOW_LIFETIME * 60
        else:
            logging.warning('set_flow_lifetime, unknown flow_assist_action: %s',
                            self.assist_action)
            self.flow_lifetime = 0  # 0= no timeout set for flow entry
        # logging.debug('setting flow_lifetime=%d seconds', self.flow_lifetime)

    def pause_processing(self):
        ''' for demo package
        '''
        # print 'DEBUG: pause_processing'
        self.is_paused = True

    def resume_processing(self):
        ''' for demo package
        '''
        # print 'DEBUG: resume_processing'
        self.is_paused = False

    def clear_flow_spec_cache(self):
        ''' for demo package
        '''
        # print 'DEBUG: clear_flow_spec_cache'
        self.dedup_cache.clear_cache()

#   def validate_action( self, action ):
#      DIRECTFLOW_ACTIONS=['drop', 'egress', 'ingress', 'output', 'set']
#      a= action.split(' ')[0]
#      if a.lower() not in DIRECTFLOW_ACTIONS:
#         logging.warn('Warning: flow action: [%s] not in %s'
#                      % (a, DIRECTFLOW_ACTIONS) )


def gen_unique_flow_name():
    ''' gen_unique_flow_name
    '''
    return 'inject_%s' % utils.ts_date(with_year=False)


def test():
    ''' # to do: update run procedure below, no longer accurate
        to run test:
        cd persist_directflow_assist_
        PYTHONPATH=$PYTHONPATH:../persist_common:../persist_pan:../../common
        #PYTHONPATH=/persist/sys/extensions/directflow_assist_pan/
        #   ../../../workspace/python_libs/jsonrpclib-master"
        export PYTHONPATH
    '''

    # python FlowAssistController.py
    syslog_msgs = [
    ]
    logging.getLogger().addHandler(logging.StreamHandler())
    logging.getLogger().setLevel(logging.DEBUG)

    print "Testing FlowAssistController"
    for msg in syslog_msgs:
        FlowAssistController().process_msg(msg)


if __name__ == "__main__":
    test()
