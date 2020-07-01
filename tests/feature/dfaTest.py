#!/usr/bin/env python
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.


import imp
import urllib2
import re
import os
import time
import glob
import collections
import logging
import sys 

import dutOperations
import data.config_common as config_common
import data.feature_test_config


LOG = logging.getLogger('testFramework')
LINKS = re.compile(r'href=\"(?P<name>directflow_assist_pan-[a-zA-Z0-9\-\_\.]*.noarch.rpm)\"')


def import_module(name, path=None):
    """Import test modules and config files"""
    try:
       f, fn, d = imp.find_module(name)
       mod = imp.load_module(name, f, fn, d)
       return mod
    except ImportError:
       print ('Unable to import %s from %s' %(name, path))


def findExtensions(url):
   LOG.info('Finding extension at %s' %(url))
   files = urllib2.urlopen(url)
   href = files.read()
   match = LINKS.findall(href)
#   rpms = []
   if match:
      LOG.info(match)
      return match


def findRpm(dir_name):
   LOG.info('Finding RPM in %s' %(dir_name))
   os.chdir(dir_name)
   rpm = glob.glob('*.noarch.rpm')
   if isinstance(rpm, str):
      rpm = [rpm]
   if not isinstance(rpm, collections.Iterable):
      LOG.error('value must be an iterable object')
      raise TypeError('value must be an iterable object')
   LOG.info('Found RPM:%s' %(rpm))
   return rpm



def assert_keys(shdirdet, fixtures):
   for key in fixtures.keys():
      if isinstance(fixtures[key], dict):
         assert_keys(shdirdet[key], fixtures[key])
      elif key != 'flow_name_regex':
         fixt = fixtures[key]
         shdir = shdirdet[key]
         if isinstance(fixtures[key], list):
            fixt = set(fixtures[key])
            shdir = set(shdirdet[key])
         assert shdir == fixt, 'expected %s, but got %s for %s' %(shdir, fixt, key)
         LOG.info('PASSED: for %s' %(key))
         print 'PASSED: for %s' %(key)


def check_tests(test, dut):
   LOG.info('Checking fixutes')
   sh_dir_det = dut.enable('show directflow detail')
   out = sh_dir_det[0]['result']
   assert (out['details']['numFlowsProgrammed'] == test['num_entries']), 'total # flows configured are wrong'
   LOG.info('PASSED: # flows configured are correct')
   print 'PASSED: # flows configured are correct'

   flows = []
   # get the flows
   for idx, key in enumerate(out['details']['status'].keys()):
      if out['details']['status'][key] == 'Flow programmed':
         if re.search(test['get_flows'], key):
            for i, flow_list in enumerate(out['flows']):
               if flow_list['name'] == key:
                  flows.append(out['flows'][i])
                  break

   # check expected # of flows, other than static
   assert len(flows) == len(test['output_directflow_entries']), 'expected number of %s is not correct' %(test['test_name'])
   LOG.info('expected number of %s is correct' %(test['test_name']))
   print 'PASSED: expected number of %s is correct' %(test['test_name'])
   
   # some how pair the fixtures to the flows and create a tuple!!
   test_pairs = [(sh, ent) for sh in flows for ent in test['output_directflow_entries'] if set(ent['match']['inInterfaces']) == set(sh['match']['inInterfaces'])]
   

   assert len(test_pairs) == len(test['output_directflow_entries']), 'the flows did not match what was expected!!\n'
   
   for pair in test_pairs:
      shdirdet = pair[0]
      fixtures = pair[1]
      LOG.info('Asserting for %s' %(shdirdet['name']))
      print 'Asserting for %s' %(shdirdet['name'])
      assert_keys(shdirdet, fixtures)


def basicTesting(duts):

   rpm = findRpm('/home/sugethakch/workspace/BS_copy_repo/')
   
   for rpm_t in rpm:
      for dut in duts:
         host = dut._connection.transport.host

         # print 'downloading extension for %s' %(host)
         # dutOperations.downlaodExtension(dut, rpms, url)

         print 'copying extension for %s' % (host)
         dutOperations.copyExtension(dut, host, rpm_t)

         print 'installing extension for %s' %(host)
         dutOperations.installExtension(dut, rpm_t)

         # TODO: check if the version reported by show extension and assist status 
         # are the same

         for mode in data.feature_test_config.test_datasets:
            config_file_name = mode[0].split('/')[-1]
            # test_data = mode[1].split('.')
            config = import_module(mode[0])
            tests = import_module(mode[1])          

            # copy over the config file (shunt mode)
            dutOperations.copy_config(config_file_name, host)
            
            # check if no flows are installed

            # setup directflow assist
            dutOperations.setup_directflow(dut)

            # start directflow assist
            dutOperations.start_flow(dut)

            for test in tests.tests:
               # send syslog 
               msg = test['input_syslog_msg']

               dutOperations.send_syslog(msg, host)

               # test show directflow detail
               check_tests(test, dut)
               dutOperations.deleteFlow(dut)

            # stop flow
            dutOperations.stopFlow(dut)
            # delete static flow
            dutOperations.deleteStaticFlow(dut)
#      dutOperations.uninstallExtension(dut, rpm_t)



