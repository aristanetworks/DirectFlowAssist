# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.

import sys
# sys.path.extend(['./persist_common', './persist_pan'])

import unittest
import time
from mock import Mock, patch
from directflow_assist.DedupCache import DeduplicationCache

DEDUP_CACHE_MAX_SIZE = 3
DEDUP_CACHE_ENTRY_LIFETIME = 1   # in minutes


class TestDedupCache(unittest.TestCase):

    def setUp(self):
        self.dedup_cache = DeduplicationCache(
            DEDUP_CACHE_MAX_SIZE, DEDUP_CACHE_ENTRY_LIFETIME)

    def tearDown(self):
        pass

    def test_clear_cache(self):
        self.dedup_cache.clear_cache()
        self.assertEqual(len(self.dedup_cache), 0)
        self.dedup_cache.insert_key('cache_test')
        self.assertNotEqual(len(self.dedup_cache), 0)

    def test_contains_key(self):
        self.dedup_cache.clear_cache()
        key = 'abc123'
        self.assertFalse(self.dedup_cache.contains_key(key))
        self.dedup_cache.insert_key(key)
        self.assertTrue(self.dedup_cache.contains_key(key))
        self.assertEqual(len(self.dedup_cache), 1)

    def test_old_key_ageing(self):
        entry_lifetime = .01  # in minutes = less than one second
        cache = DeduplicationCache(DEDUP_CACHE_MAX_SIZE, entry_lifetime)
        key = 'foobar'
        cache.insert_key(key)
        self.assertTrue(cache.contains_key(key))
        self.assertEqual(len(cache), 1)
        time.sleep(1)
        self.assertFalse(cache.contains_key(key))
        self.assertEqual(len(cache), 0)

    def test_cache_size_maintenance(self):
        # should delete first key when size > max
        self.dedup_cache.clear_cache()
        self.dedup_cache.insert_key('key1')
        self.dedup_cache.insert_key('key2')
        self.dedup_cache.insert_key('key3')
        self.assertEqual(len(self.dedup_cache), 3)

        self.dedup_cache.insert_key('key4')
        self.assertEqual(len(self.dedup_cache), 3)
        self.assertFalse(self.dedup_cache.contains_key('key1'))
        self.assertTrue(self.dedup_cache.contains_key('key2'))
        self.assertTrue(self.dedup_cache.contains_key('key3'))
        self.assertTrue(self.dedup_cache.contains_key('key4'))
        self.dedup_cache.clear_cache()


if __name__ == '__main__':
    unittest.main()
