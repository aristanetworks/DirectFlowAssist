#!/usr/bin/env python2.7

''' build utilities
'''

import sys
import re
import time

NUM_STR = 'build_num='
DATE_STR = 'build_date='
BUILD_STATS_FILE = ''


def increment_minor_version(version_file):
    ''' increment last digits position after a dot
    '''
    print 'running build_utils.increment_minor_version()'
    # sample formats __version__ =: "0.5.dev", "0.23.beta", "0.9.2-EFT"
    old_ver = ''
    with open(version_file, 'r+') as ver_file:  # r+ = open for read & write
        file_data = ver_file.readlines()
        for line in file_data:
            if '__version__' in line:
                old_ver = line
                break
        if not old_ver:
            print 'ERROR: Unable to locate __version__ in %s' % version_file
            return
        print 'old version: %s' % old_ver.strip()
        mobj = re.search(r'^(.*)\.(\d{1,3})(.*)"', old_ver)
        if mobj:
            prefix = mobj.group(1)
            minor_ver = int(mobj.group(2))
            label = mobj.group(3)
        else:
            print 'Error parsing version'
            return
        minor_ver += 1
        new_ver = '%s.%d%s"' % (prefix, minor_ver, label)
        print 'new version: %s' % new_ver
        file_data = "".join(file_data)
        file_data = file_data.replace(old_ver, new_ver)
        ver_file.seek(0)
        ver_file.writelines(file_data)

# def increment_minor_version(version_file):
#     ''' increment minor number for prerelease builds
#     '''
#     print 'running build_utils.increment_minor_version()'
#     # format: __version__ = "0.5.dev"
#     old_ver = ''
#     with open(version_file, 'r+') as ver_file:  # r+ = open for read & write
#         for line in ver_file:
#             if '__version__' in line:
#                 old_ver = line
#                 break
#         if not old_ver:
#             print 'ERROR: Unable to locate __version__ in %s' % version_file
#             return
#         print 'old version: %s' % old_ver.strip()
#         mobj = re.search(r'^(.*)\.(\d{1,5})\.(dev|beta|demo)"', old_ver)
#         if mobj:
#             prefix = mobj.group(1)
#             minor_ver = int(mobj.group(2))
#             label = mobj.group(3)
#         else:
#             print 'Error parsing version'
#             return
#         minor_ver += 1
#         new_ver = '%s.%d.%s"' % (prefix, minor_ver, label)
#         print 'new version: %s' % new_ver
#         #ver_file.seek(0)
#         ver_file.writelines(new_ver + '\n')


def increment_build_num():
    ''' inc build number using date
    '''
    ver_file = open(BUILD_STATS_FILE, 'r+')
    line = ver_file.readline()  # first line contains last build number
    mobj = re.search(r'^' + NUM_STR + r'(\d{1,5})', line)
    if mobj is None:
        print ('Error parsing build # from %s, NOT incrementing build #'
               % BUILD_STATS_FILE)
        return
    else:
        bnum = int(mobj.group(1))
    bnum += 1
    print 'build_num: %d' % bnum
    ver_file.seek(0)
    ver_file.writelines(NUM_STR + str(bnum) + '\n')
    ver_file.writelines(DATE_STR + '"' + time.asctime() + '"\n')
    ver_file.close()


def main():
    ''' start here
    '''
    print 'build_tools sys.argv: %s' % sys.argv
    if len(sys.argv) == 3 and sys.argv[1] == "inc":
        increment_minor_version(sys.argv[2])
    else:
        print 'Unknown build_utils command'


if __name__ == '__main__':
    main()
    # test()
