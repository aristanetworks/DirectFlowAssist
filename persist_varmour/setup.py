''' package definition
'''

from setuptools import setup
from directflow_assist import __version__

PERSIST_DIR = '/persist/sys/extensions/directflow_assist/'
PYTHON_PKG_NAME = 'directflow_assist'
INSTALL_PKG_NAME = 'directflow_assist_varmour'

setup(name=INSTALL_PKG_NAME,
      version=__version__,
      description='DirectFlow Assist for vArmour',
      # author='Ben C. DeBolle',
      author='Arista Networks, Inc.',     # displays in Vendor field for RPMs
      author_email='bdebolle@arista.com',
      packages=[PYTHON_PKG_NAME, PYTHON_PKG_NAME + '.common'],
      scripts=['assist'],
      data_files=[(PERSIST_DIR, ['LICENSE',
                                 'README.txt',
                                 'config_common.py',
                                 'config.py']),
                  ('/etc/logrotate.d/', ['dfa_logrotate'])],
      zip_safe=False,   # need to access data files via standard file system
      platforms='linux',
      license='BSD-new',
      url='https://github.com/arista-eosext/directflow-assist',
      long_description='''
Arista Networks, Inc.
DirectFlow Assist for vArmour
EOS Extension written in python
Runs on Arista switches that support DirectFlow.
See the README at /persist/sys/extensions/directflow_assist/README.txt
for minimum EOS version and additional info.
''')
