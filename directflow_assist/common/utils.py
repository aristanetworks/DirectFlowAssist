#!/usr/bin/env python2.7
#
# Engineer:  Ben C. DeBolle, bdebolle@arista.com
# Copyright (c) 2013-2015 Arista Networks, Inc.  All rights reserved
# Arista Networks, Inc. Confidential and Proprietary.
# pylint: disable = invalid-name, too-many-branches
#
''' shared utils
'''

import sys
import os
import re
import types
import json
import subprocess
import logging
from logging.handlers import SysLogHandler
import time
import datetime

TCP = 6
UDP = 17

EOS_RELEASE_STR = '/etc/Eos-release'
IP_PROTOCOL = {
    '1': 'ICMP',
    '2': 'IGMP',
    '4': 'IPv4',
    '6': 'TCP',
    '8': 'EGP',
    '17': 'UDP',
    '41': 'IPv6',
    '46': 'RSVP',
    '47': 'GRE',
    '89': 'OSPFIGP',
}

# based on info at http://www.iana.org/assignments/service-names-port-numbers
APP_PORT_NUMBERS = {
    '20': ['FTP_Data', TCP, UDP],
    '21': ['FTP_Control', TCP, UDP],
    '22': ['SSH', TCP, UDP],
    '23': ['Telnet', TCP, UDP],
    '25': ['SMTP', TCP, UDP],
    '53': ['DNS', TCP, UDP],
    '69': ['TFTP', TCP, UDP],
    '80': ['HTTP', TCP],
    '110': ['POP3', TCP],
    '115': ('SFTP', TCP),
    '143': ['IMAP', TCP],
    '161': ['SNMP', UDP],
    '162': ['SNMPTRAP', TCP, UDP],
    '179': ['BGP', TCP],
    '389': ['LDAP', TCP, UDP],
    '443': ['HTTPS', TCP],
    '546': ['DHCP_client', TCP, UDP],
    '547': ['DHCP_server', TCP, UDP],
}


def determine_app(ip_protocol, port):
    ''' determine application name from IP protocol and port number
    '''
    app = 'unknown'
    ip_protocol_name = IP_PROTOCOL.get(str(ip_protocol), None)
    if ip_protocol_name:
        if 'ICMP' == ip_protocol_name:
            return 'ping'  # guess=ping, no ICMP type field avail. to resolve
        app_entry = APP_PORT_NUMBERS.get(str(port), None)
        if app_entry and int(ip_protocol) in app_entry:
            app = app_entry[0]
    return app


def exec_shell_cmd(cmd, echo=True):
    ''' exec a shell command
    '''
    if echo:
        print 'exec_shell_cmd: %s' % cmd
    subprocess.call(cmd, shell=True)


def exec_shell_cmd_env(cmd, env):         # with environment dict
    ''' exec a shell command with passed environment
    '''
    print 'exec_shell_cmd_env: %s' % cmd
    subprocess.call(cmd, shell=True, env=env)


def utime():
    ''' Current UTC time in seconds since unix epoch 1/1/1970, aka Unix time
    '''
    return int(time.time())


def ts_hms24():
    ''' hour:minute:seconds 24 hour timestamp, e.g. 21:27:25
    '''
    return time.strftime('%H:%M:%S', time.localtime())


def ts_hms():
    ''' hour:minute:seconds AM/PM timestamp, e.g. 09:27:19_PM
    '''
    return time.strftime('%I:%M:%S_%p', time.localtime())


def ts_date(with_year=True, ms_prec=6):
    ''' ms_prec is the number of digits of precision for microseconds field
    '''
    if with_year:
        tstamp = datetime.datetime.now().strftime('%Y%b%d_%H:%M:%S.%f')
    else:
        tstamp = datetime.datetime.now().strftime('%b%d_%H:%M:%S.%f')
    prec = 6 - ms_prec   # %f provides 6 digits of precision
    tstamp = tstamp[:len(tstamp) - prec]
    if ms_prec == 0:
        tstamp = tstamp.replace('.', '')
    return tstamp


def format_ts(tstamp, with_year=True, with_sec=True):
    ''' time.ctime() convert a time expressed in seconds since the epoch to a
        string representing local time.
    '''
    fts = time.ctime(tstamp)[4:]      # remove day of week
    if not with_year:
        fts = fts[:-5]            # remove day of week and year
    if not with_sec:
        fts = re.sub(r'(\d\d:\d\d):\d\d', r'\1', fts)
        # mo= re.search( r'(.*):\d\d(.*)', fts )
        # fts= mo.group(1) + mo.group(2)
    return fts


def dump_dict_sorted(d):
    ''' dump
    '''
    for key in sorted(d.keys()):
        print key, d[key]


def dump_dict(*args, **kwargs):
    ''' dump
    '''
    print unpack_struct(*args, **kwargs)
    print


def unpack_dict_by(adict, keys, sp=3):
    ''' dump dict
    '''
    out = ''
    longest_key = longest(keys)
    for k in keys:
        if k in adict:
            out += '%s%s  : %s\n' % (' ' * sp, k.ljust(longest_key),
                                     adict[k])
    return out


def dump_list(lst):
    ''' dump list
    '''
    out = ''
    for item in lst:
        out += '%s\n' % (item,)
    return out


def dump_json(data):
    ''' dump
    '''
    print 'JSON: \n%s\n' % json.dumps(data, indent=2)


def unpack(struct, *args, **kwargs):
    ''' dump
    '''
    # print 'RAW: \n%s\n' % struct
    return unpack_struct(struct, *args, **kwargs)


def unpack_struct(data, spc=0, suppress_empty=False, show_type=False):
    ''' dump
    '''
    # fix: chg: suppress_empty to show_empty
    # fix: chg: unpact_struct kwargs on re-entrant
    out = ''
    # out+= 'Type= %s' % type(data)
    if isinstance(data, types.DictType):
        out += '%s%s (keys=%d)\n' % (' ' * spc, 'DICT', len(data.keys()))
        spc += 3
        longest_key = longest(data.keys())
        for k, v in data.items():
            if v or not suppress_empty:
                out += ('%s%s  : %s\n' %
                        (' ' * spc, k.ljust(longest_key),
                         unpack_struct(v, spc, suppress_empty=suppress_empty,
                                       show_type=show_type).strip()))
    elif isinstance(data, types.ListType):
        out += '%s%s (len=%d)\n' % (' ' * spc, 'LIST', len(data))
        if data:
            for j, e in enumerate(data):
                if j == 0:
                    spaces = spc + 3   # initial indentation
                else:
                    spaces = 2       # list item separation
                out += unpack_struct(e, spc=spaces,
                                     suppress_empty=suppress_empty,
                                     show_type=show_type) + ','
    elif isinstance(data, types.TupleType):
        out += '%s%s (len=%d)\n' % (' ' * spc, 'TUPLE', len(data))
        if data:
            for e in data:
                out += unpack_struct(e, spc=spc + 3,
                                     suppress_empty=suppress_empty,
                                     show_type=show_type) + '\n'
    elif isinstance(data, types.IntType):
        out += '%s%s%s' % (' ' * spc, data, ' (int)' if show_type else '')
    elif isinstance(data, types.LongType):
        out += '%s%s%s' % (' ' * spc, data, ' (LONG)' if show_type else '')
    elif isinstance(data, types.FloatType):
        out += '%s%s%s' % (' ' * spc, data, ' (FLOAT)' if show_type else '')
    elif isinstance(data, types.StringType):
        out += '%s%s%s' % (' ' * spc, data, ' (STR)' if show_type else '')
    elif isinstance(data, types.UnicodeType):
        out += '%s%s%s' % (' ' * spc, data, ' (uni)' if show_type else '')
    elif isinstance(data, types.BooleanType):
        out += '%s%s%s' % (' ' * spc, data, ' (BOOL)' if show_type else '')
    elif isinstance(data, types.ObjectType):
        out += '%s%s%s' % (' ' * spc, data, ' (obj)' if show_type else '')
    elif isinstance(data, types.ClassType):
        out += '%s%s= %s' % (' ' * spc, ' CLASS', type(data))
    elif isinstance(data, types.FileType):
        out += '%s%s size= %d' % (' ' * spc, 'FILE', len(data))
# Vendor Classes
#    elif isinstance(data, "<class 'python_libs.pyhop.PyHopObject'>" ):
#       out += ' '*spc+'PyHopObject'
    else:
        out += 'UNKNOWN Type= %s' % type(data)  # ToDo: more unpacking
    return out


def get_exec_envt():
    ''' returns info about python's current exec environment
    '''
    env = []
    env.append('running on: %s' % get_EOS_release())
    env.append('python version: %s' % sys.version)
    env.append('python executable: %s' % sys.executable)
    env.append('user: %s, uid: %s, euid: %s, gid: %s, egid: %s' %
               (os.environ.get('USER'), os.getuid(), os.geteuid(),
                os.getgid(), os.getegid()))
    env.append('current working dir: %s' % os.getcwd())
    env.append('current logging level: %s' %
               logging.getLevelName(
                   logging.getLogger().getEffectiveLevel()))
    return '\n'.join(env)


def dump_envt():
    ''' dump
    '''
    os.system('uname -a')
    os.system('cat /etc/*-release')
    print '\nPython environment:'
    print ' version: %s' % sys.version
    print ' user: %s' % os.environ.get('USER')
    print ' uid: %s' % os.getuid()
    print ' euid: %s' % os.geteuid()
    print ' gid: %s' % os.getgid()
    print ' egid: %s' % os.getegid()
    print ' current working dir: %s' % os.getcwd()
    print ' hostname: %s' % os.environ.get('HOSTNAME')
    print ' hosttype: %s' % os.environ.get('HOSTTYPE')
    print ' cpu: %s' % os.environ.get('CPU')
    print ' platform: %s' % sys.platform
    # print ' prefix: %s' % sys.prefix
    print ' executable: %s' % sys.executable
    print ' argv: %s' % sys.argv


def dump_python_modules():
    ''' dump
    '''
    print 'python sys.modules:'
    for m in sys.modules:
        print '  %s' % m


def dump_python_path():
    ''' dump
    '''
    print 'python sys.path:'
    for p in sys.path:
        print '  %s' % p


def longest(mlist):
    ''' return length of longest string in mlist
    '''
    max_len = 0
    for j in mlist:
        if len(j) > max_len:
            max_len = len(j)
    return max_len


def unique_int():
    ''' return a unique int based on current time
    '''
    u = '%.23f' % time.time()
    return u


def is_installed_on_switch():
    ''' return true if running on EOS switch
    '''
    return os.path.exists(EOS_RELEASE_STR)


def get_EOS_release():
    ''' assumes running on switch
        see arista.py for get version via eAPI
    '''
    if os.path.exists(EOS_RELEASE_STR):
        with open(EOS_RELEASE_STR) as f:
            eos_ver = f.read()
            return eos_ver.strip()


def format_cli_cmds_for_printing(cmds_list):
    ''' handle special case of an embedded dictionary for configuring
        comments that end with EOF etc.
    '''
    out = []
    for cmd in cmds_list:
        if not isinstance(cmd, types.StringType):
            # print '%s not a str' % cmd
            out.append(str(cmd))
        else:
            out.append(cmd)
    return ('\n  ').join(out)


def scrub_flow_name(name):
    ''' Replace unsupported characters with reasonable substitutes in
        DirectFlow flow names.
    '''
    name = name.replace(' ', '_')
    name = name.replace(',', '_')
    name = name.replace('.', '-')
    name = name.replace('/', ':')
    return name


def scrub_mon_session_name(name):
    ''' Replace unsupported characters with reasonable substitutes.
        Same naming rules as DirectFlow names.
    '''
    return scrub_flow_name(name)


def get_code_install_dir():
    ''' As initialized upon program startup, the first item of this list,
         path[0], is the directory containing the script that was used to
         invoke Python
    '''
    path = sys.path[0]
    # print 'get_code_install_dir: %s' % path
    return path


def setup_logging(log_filename='./noname.log', min_log_level=logging.DEBUG):
    ''' setup_logging
    '''
    ensure_logfile_exists(log_filename)
    logging.basicConfig(filename=log_filename,
                        level=min_log_level,
                        format='%(asctime)s %(levelname)s  %(message)s',
                        datefmt='%b %d %H:%M:%S')


def setup_logging_to_external_syslog_server(server_ip, udp_port):
    ''' setup_logging
    '''
    print 'setup external syslog server ip: %s, udp_port: %s' % (server_ip, udp_port)
    syslog_server = SysLogHandler(address=(server_ip, udp_port))
    logging.getLogger().addHandler(syslog_server)


def ensure_logfile_exists(filename):
    ''' creat file and path if necessary, and make writable by non-root
        processes
    '''
    if not os.path.exists(filename):
        print 'Creating file: %s' % filename
        exec_shell_cmd('sudo touch %s' % filename)
        exec_shell_cmd('sudo chgrp eosadmin %s' % filename)
        exec_shell_cmd('sudo chmod 664 %s' % filename)

#      (path, fname)= os.path.split( filename )
#      if path and not os.path.exists( path ):
#         os.mkdir( path )
#
# f= open( filename,'a+')  # create it [alt. similar to 'touch':
#                          # os.utime(path, None)]
#      f.close()
#      cur_mode = os.stat( filename ).st_mode
#      mode= (cur_mode | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH
#             | stat.S_IWOTH)
#      os.chmod( filename, mode )


def extract_iso8601_timestamp(msg, convert_to_utc=False,
                              timestamp_format='%Y-%m-%d %H:%M:%S'):
    '''  extract and convert iso8601 formatted timestamp to
         a more conventional format.
    sample: <85>Feb 23 09:27:10+02:00 192.168.133.152 Action="accept"
    sample: <85>Feb 23 09:27:10-07:30 192.168.133.152 Action="accept"
    sample: <85>Mar 05 09:15:37--8:00 172.22.28.54 Action="accept" ## NOTE '--'
    '''

    mobj = re.match(r'(<\d{1,6}>)?(.*?)([+-])-?(\d{1,2}):(\d\d) \d{1,3}\.', msg)
    if not mobj:
        return None
    raw_ts = mobj.group(2)
    utc_offset_direction = mobj.group(3)
    utc_offset_hours = mobj.group(4)
    utc_offset_mins = mobj.group(5)
    # logging.debug('raw_ts: %s, utc_offset_direction: %s utc_offset_hours: %s '
    #      'utc_offset_mins: %s' % (raw_ts, utc_offset_direction,
    #                               utc_offset_hours, utc_offset_mins))
    this_year = time.gmtime()[0]
    ts_with_year = '%s %s' % (this_year, raw_ts)
    utc_base = datetime.datetime.strptime(ts_with_year, '%Y %b %d %H:%M:%S')
    if convert_to_utc:
        delta = datetime.timedelta(hours=int(utc_offset_hours),
                                   minutes=int(utc_offset_mins))
        offset_multiplier = int('%s%s' % (utc_offset_direction, '1'))
        local_ts = utc_base + (offset_multiplier * delta)
        # logging.debug('utc_base: %s, delta: %s, local_ts: %s' %
        #           (utc_base, delta, local_ts))
    else:
        local_ts = utc_base
    timestamp = local_ts.strftime(timestamp_format)
    return timestamp


def is_valid_ip_addr(ip):
    ''' check valid IPv4 address
    '''
    if ip and ip.count('.') == 3 and ip != '0.0.0.0':
        regex = r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        mo = re.match(regex, ip)
        if mo:
            for j in [1, 2, 3, 4]:
                num = int(mo.group(j))
                if num > 255:
                    return False
            return True  # valid IP
    return False

# ------------------------------------------------------------------------------


def test_determine_app():
    ''' test
    '''
    try:
        assert determine_app(0, 0) == 'unknown', 'expected: unknown'
        assert determine_app(0, 22) == 'unknown', 'expected: unknown'
        assert determine_app(1, 22) == 'ping', 'expected: ping'
        assert determine_app(6, 22) == 'SSH', 'expected: SSH'
        assert determine_app(17, 22) == 'SSH', 'expected: SSH'
        assert determine_app(17, 0) == 'unknown', 'expected: unknown'
        assert determine_app(6, 443) == 'HTTPS', 'expected: HTTPS'
        assert determine_app(6, 80) == 'HTTP', 'expected: HTTP'
        assert determine_app(17, 80) == 'unknown', 'expected: unknown'
        assert determine_app(6, 161) == 'unknown', 'expected: unknown'
        assert determine_app(17, 161) == 'SNMP', 'expected: SNMP'
    except AssertionError as err:
        print 'FAIL %s' % err.message


def test_logging():
    ''' test
    '''
    setup_logging('TEST_LOGGING', '1.0_DEV')
    logging.debug('logging test, level should be DEBUG')
    logging.info('logging test, level should be INFO')
    logging.warning('logging test, level should be WARNING')
    logging.error('logging test, level should be ERROR')
    logging.critical('logging test, level should be CRITICAL')


def test_timestamps():
    ''' test
    '''
    print 'localtime: %s ' % time.localtime()
    print 'asctime: %s ' % time.asctime()
    print format_ts(utime())
    print format_ts(utime(), with_year=False)
    print format_ts(utime(), with_year=False, with_sec=False)
    print ts_hms()
    print ts_hms24()
    print ts_date(with_year=False)
    print ts_date(with_year=True)
    print ts_date(with_year=True, ms_prec=0)
    print ts_date(with_year=False, ms_prec=0)
    print ts_date(with_year=True, ms_prec=9)
    print ts_date(with_year=False, ms_prec=9)


def test_logfile():
    ''' test
    '''
    ensure_logfile_exists('existingfile')  # setup file
    ensure_logfile_exists('existingdir/afile')   # setup empty dir
    ensure_logfile_exists('newfile')
    ensure_logfile_exists('newdir/newfile')


def test_ip_validation():
    ''' test
    '''
    print 'test_ip_validation: first 2 s/b True, rest False'
    print is_valid_ip_addr('1.2.3.4')
    print is_valid_ip_addr('255.255.255.255')
    print is_valid_ip_addr('0.0.0.0')
    print is_valid_ip_addr('1')
    print is_valid_ip_addr('1.2')
    print is_valid_ip_addr('1.2.3')
    print is_valid_ip_addr('1.2.3.')
    print is_valid_ip_addr('1.2.3.4.5')
    print is_valid_ip_addr('1.2.3.999')
    print is_valid_ip_addr(None)
    print is_valid_ip_addr('')


if __name__ == '__main__':
    test_determine_app()
    # exec_shell_cmd('who')
    # dump_envt()
    # test_timestamps()
    # print ts_date( with_year=False, ms_prec=0 )
    # test_ip_validation()
