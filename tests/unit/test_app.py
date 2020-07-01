#
# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.

import unittest
from mock import Mock, patch
from directflow_assist import app


class TestDfaApp(unittest.TestCase):

    def setUp(self):
        # self.cli_no_cmd = open(get_fixture('dfa_cli_no_cmd.text')).read()
        pass

    def tearDown(self):
        pass

    def test_unittest_framework(self):
        self.assertEqual('this', 'this')
        self.assertNotEqual('this', 'that')
        self.assertTrue(1 == 1)
        self.assertFalse(1 == 2)
        with self.assertRaises(ZeroDivisionError):
            bad_math = 1 / 0


if __name__ == '__main__':
    unittest.main()
