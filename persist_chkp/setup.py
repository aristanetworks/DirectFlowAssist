''' package definition
'''

# from distutils.core import setup
from setuptools import setup
from directflow_assist import __version__

PERSIST_DIR = '/persist/sys/extensions/directflow_assist/'
PYTHON_PKG_NAME = 'directflow_assist'
INSTALL_PKG_NAME = 'directflow_assist_chkp'

setup(name=INSTALL_PKG_NAME,
      version=__version__,
      description='DirectFlow Assist for Check Point Firewalls',
      # author='Ben C. DeBolle',
      author='Arista Networks, Inc.',     # displays in Vendor field for RPMs
      author_email='bdebolle@arista.com',
      packages=[PYTHON_PKG_NAME, PYTHON_PKG_NAME + '.common'],
      scripts=['assist'],
      data_files=[(PERSIST_DIR, ['LICENSE',
                                 'README.txt',
                                 'config_common.py',
                                 'config.py',
                                 'rootCA2.crt',
                                 'dfa_tor1.crt',
                                 'dfa_tor1.key']),
                  ('/etc/logrotate.d/', ['dfa_logrotate'])],
      zip_safe=False,   # need to access data files via standard file system
      platforms='linux',
      license='BSD-new',
      url='https://github.com/arista-eosext/directflow-assist',
      long_description='''
Arista Networks, Inc.
DirectFlow Assist for Check Point Firewalls
EOS Extension written in python
Runs on Arista switches that support DirectFlow.
See the README at /persist/sys/extensions/directflow_assist/README.txt
for minimum EOS version and additional info.
''')
