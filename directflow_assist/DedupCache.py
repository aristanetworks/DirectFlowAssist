#!/usr/bin/env python2.7
#
# Copyright (c) 2013-2015 Arista Networks, Inc.  All rights reserved
# Arista Networks, Inc. Confidential and Proprietary.

''' Deduplication cache
'''

import logging
import time
from collections import OrderedDict


class DeduplicationCache(object):
    ''' Deduplication cache
    '''
    def __init__(self, max_cache_size, entry_lifetime):
        self.max_cache_size = max_cache_size
        self.entry_lifetime = entry_lifetime
        self.dedup_cache = OrderedDict()

    def __len__(self):
        return len(self.dedup_cache)

    def contains_key(self, key):
        ''' returns True if key is already in the cache
        '''
        if key not in self.dedup_cache:
            return False
        else:
            # check if cache entry is too old
            insert_time = self.dedup_cache[key]
            age = time.time() - insert_time
            if age >= (self.entry_lifetime * 60):
                logging.debug('expired dedup cache key: %s age: %d', key, age)
                del self.dedup_cache[key]  # FIFO so must delete (not update)
                return False
            else:
                return True

    def insert_key(self, key):
        ''' add key to cache
        '''
        if key not in self.dedup_cache:
            logging.debug('dedup cache: adding new key: %s', key)
            self.dedup_cache[key] = time.time()   # add new entry
            self.cache_size_maintenance()
        else:
            logging.warning('key already in cache, key: %s', key)

    def cache_size_maintenance(self):
        ''' truncate cache to maintain size
        '''
        while len(self.dedup_cache) > self.max_cache_size:
            deleted = self.dedup_cache.popitem(last=False)
            logging.debug('dedup cache: size maintenance, deleting: %s',
                          deleted)
        logging.debug('dedup_cache size=%d keys', len(self.dedup_cache))

    def clear_cache(self):
        ''' remove all cache entries
        '''
        logging.info('clearing dedup_cache')
        self.dedup_cache.clear()

    def dump_dedup_cache(self):
        ''' dump all cache entries to log file
        '''
        logging.debug('dumping dedup_cache len=%d', len(self.dedup_cache))
        now = time.time()
        for (key, time_stamp) in self.dedup_cache.items():
            logging.debug('  key: [%s]  age: %d', key, (now - time_stamp))
