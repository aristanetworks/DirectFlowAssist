#!/usr/bin/env python
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.


import subprocess
import re
import json
import os 
import pyeapi

import beginTest
import dfaTest
import endTest

def main():
   duts = beginTest.beginTest()
   dfaTest.basicTesting(duts)
   endTest.endTest(duts)
   
if __name__ == '__main__':
   main()
