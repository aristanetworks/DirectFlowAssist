#!/usr/bin/env python2.7
#
# Engineer:  Ben C. DeBolle, bdebolle@arista.com
# Copyright (c) 2013-2015 Arista Networks, Inc.  All rights reserved
# Arista Networks, Inc. Confidential and Proprietary.
#
# pylint: disable = too-many-arguments

''' helper client for Arista eAPI
'''

import jsonrpclib
import types
import time
import re

ENGINEERING_VERS = {'gat2VxlanRouting': '4.15.2'}
UNIX_UDS = 'unix:/var/run/command-api.sock'  # unix domain socket (local eAPI)


class AristaEOS(object):
    ''' helper client to Arista eAPI
        default transport protocol is HTTPS
    '''
    def __init__(self, switch_ip, username, passwd, protocol, print_eapi_latency=False):
        try:
            if protocol.upper() == 'UDS' or protocol.upper().startswith('UNIX'):
                switch_url = UNIX_UDS
            else:
                switch_url = '%s://%s:%s@%s/command-api' % (protocol, username,
                                                            passwd, switch_ip)
            # print 'switch_url=%s' % switch_url
            self.switch = jsonrpclib.Server(switch_url)
            self.switch_ip = switch_ip
            self.print_eapi_latency = print_eapi_latency
        except Exception as ex:
            print ('ERROR AristaEOS.__init__(): proto=%s, ip=%s, user=%s, passwd=%s, '
                   'url=%s' % (protocol, switch_ip, username, passwd, switch_url))
            raise ex

    def exec_eapi_cmds(self, cmds, output_format='json'):
        ''' sends cli cmds via eAPI to EOS, returns json response object
            output format may be: json or text;  use text for cli
            commands that have not been converted to json yet
        '''
        # print 'sending cmd=%s' %cmds
        start_ts = time.time()
        resp = self.switch.runCmds(1, cmds, output_format)
        if self.print_eapi_latency:
            print 'eapi latency: %.3fs  cmds: %s' % (time.time() - start_ts, cmds)
        jsonrpclib.history.clear()  # saves memory; history saves all req & resp
        # warn_on_large_request(cmds, resp)
        # print utils.unpack( resp, show_type=True )
        return resp

    def in_running_config(self, config_line):
        ''' returns true if config_line found in running-config
        '''
        cmds = ['enable', 'show running-config section %s' % config_line]
        resp = self.exec_eapi_cmds(cmds, output_format='text')
        # print 'in_running_config() resp: %s' % resp
        output = resp[1]["output"]
        print 'debug: AristaEOS.in_running_config(): [%s]' % output
        if output:
            return True
        else:
            return False

    def get_eos_version(self):
        ''' returns EOS version
        '''
        resp = self.exec_eapi_cmds(['show version'])
        return resp[0]["version"]

    def eos_version_at_least(self, min_version):
        ''' compare version
        '''
        version = self.get_eos_version()
        return ver_same_or_greater_than(version, min_version)

# class AristaCVX( object ):
#
# class AristaCVP( object ):


def is_empty_eapi_response(resp):
    ''' used to check if eos config command response has all empty dicts
    '''
    if not isinstance(resp, types.ListType):
        print 'response type not List'
        return False
    for dict_data in resp:
        if isinstance(dict_data, types.DictType):
            if len(dict_data) != 0:
                return False
        else:
            print 'error: unexpected type'
            return False
    return True


#     def warn_on_large_request(cmds, resp):
#         ''' log warning on large eapi requests
#         '''
#         warn_size = 100
#         cmds_len = len(cmds)
#         resp_len = len(resp)
#         if cmds_len > warn_size or resp_len > warn_size:
#             print ('DBG: large eapi transaction cmds_len: %d, resp_len: %d'
#                   % (cmds_len, resp_len))


def convert_version_string(ver):
    ''' convert to simplify comparisons
    '''
    # print 'convert_version_string: %s ' % ver
    # remove alpha chars
    try:
        numeric_ver = []
        for char in ver:
            if char.isdigit() or char == '.':
                numeric_ver.append(char)
        nver = ''.join(numeric_ver)
        # print 'numeric only: %s ' % nver
        # convert to float
        ver = nver.split('.')
        fver = float(ver[0])
        fver += float(ver[1]) / 100
        fver += float(ver[2]) / 10000
        # print 'as float: %s ' % fver
        return fver
    except Exception as ex:
        print ex
        print 'Unable to convert_version_string: %s' % ver


def ver_same_or_greater_than(version, min_version):
    ''' version comparison, suitable for most current EOS version strings.
        Also see: from distutils import version; LooseVersion, StrictVersion
    '''
    # remap engineering version to a more helpful version for comparisons
    # e.g. "4.13.0-1826244.flbocadev.1 (engineering build)" is after 4.13.6F
    if "engineering" in version:
        known_engr_ver = False
        # map project name to a useful version (may not be correct final release version)
        for project_name, mapped_ver in ENGINEERING_VERS.iteritems():
            if project_name in version:
                print 'remapping [%s] to [%s]' % (version, mapped_ver)
                version = mapped_ver
                known_engr_ver = True
        if not known_engr_ver:
            mobj = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}).*?', version)
            if mobj:
                version = mobj.group(1)
                print 'truncated ver string: %s' % version

    ver = convert_version_string(version)
    min_ver = convert_version_string(min_version)
    # return version.LooseVersion( version ) >= version.LooseVersion(
    # min_version )
    return ver >= min_ver


def test():
    ''' test
    '''
    assert ver_same_or_greater_than("4.13.7M", "4.13.6F")
    assert ver_same_or_greater_than("4.12.4", "4.11.2")
    assert ver_same_or_greater_than("4.0.0", "3.19.58")
    assert ver_same_or_greater_than(
        '4.14.3-2415434.gat2VxlanRouting (engineering build)', '4.15.2')
    assert ver_same_or_greater_than(
        '4.15.3-3456.dummy_test (engineering build)', '4.15.3')
    assert ver_same_or_greater_than(
        'MS4.15.3-3456.dummy_test (engineering build)', '4.15.3')
    print 'pass'


if __name__ == "__main__":
    test()
