''' package definition
'''


from setuptools import setup
from directflow_assist import __version__

PERSIST_DIR = '/persist/sys/extensions/directflow_assist/'
PYTHON_PKG_NAME = 'directflow_assist'
INSTALL_PKG_NAME = 'directflow_assist_pan_demo'

setup(name=INSTALL_PKG_NAME,
      version=__version__,
      description='DirectFlow Assist for PAN Firewalls, DEMO',
      # author='Ben C. DeBolle',
      author='Arista Networks, Inc.',     # displays in Vendor field for RPMs
      author_email='bdebolle@arista.com',
      packages=[PYTHON_PKG_NAME, PYTHON_PKG_NAME + '.common'],
      scripts=['assist'],
      data_files=[(PERSIST_DIR, ['LICENSE',
                                 'README.txt',
                                 'DEMO_README.txt',
                                 'assist.py',
                                 'config_common.py',
                                 'config.py',
                                 'rootCA2.crt']),
                  ('/etc/logrotate.d/', ['dfa_pan_logrotate'])],
      # code needs to access data files via standard file system
      zip_safe=False,
      platforms='linux',
      license='BSD (3-clause)',
      url='https://github.com/arista-eosext/directflow-assist',
      long_description='''
Arista Networks, Inc.
DirectFlow Assist for Palo Alto Networks Firewalls, DEMO
EOS Extension written in python
Runs on 7050/7050X switches.
See README.txt for more info''')
