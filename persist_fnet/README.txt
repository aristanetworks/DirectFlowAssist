
Arista Networks, Inc.
EOS Extension: DirectFlow Assist for Fortinet Firewall 
-------------------------------------------------------------------------------

Minimum EOS version: 4.14.5F or later
This extension has been test with Fortigate model 500D, SW v5.2.2
Supported firewall deployment mode(s): L2

-------------------------------------------------------------------------------
Installation and Operation:

1) Install extension from EOS cli:
  copy scp:user@server/path/directflow_assist_<name_and_version>.rpm extension:
  or
  copy http://server/path/directflow_assist_<name_and_version>.rpm extension:
  dir extension:
  extension directflow_assist_<name_and_version>.rpm
  show extensions [detail]
  copy installed-extensions boot-extensions

  This will install the DirectFlow Assist python package at: 
  /usr/lib/python2.7/site-packages/directflow_assist

  the config file, README and LICENSE at:
  /persist/sys/extensions/directflow_assist

  the startup script at:
  /usr/bin/assist
  
  a log rotation file at:
  /etc/logrotate.d/dfa_logrotate

  After running 'assist setup' a log file will be available at:
  /var/log/directflow_assist.log

  When DFA is running there will be a file that contains the process id at:
  /var/run/directflow_assist.pid

2) Ensure eAPI is enabled for local unix domain sockets; 'protocol unix-socket'.
switch#show management api http-commands 
Enabled:            Yes
...
Unix Socket server: running, no authentication
...

3) Connect firewall interfaces to switch interfaces

4) Edit the config file to define interfaces used to connect the firewall.
   bash
   cd /persist/sys/extensions/directflow_assist
   vi config.py
   Carefully input the Zone A and B interfaces.

   * For INLINE_MODE only the Zone A interfaces are needed.
   * For MIRROR_MODE only SWITCH_INTERFACES_TO_FW_TAP and
     SWITCH_INTERFACES_TO_BE_MIRRORED interfaces are needed.

5) From bash:  assist setup 
   this will: create the static port-binding flows to send traffic through
              the attached firewall and create a log file at /var/log/

   IMPORTANT!: After the static flow entries have been created be sure to do
   a 'copy running-config startup-config' from the EOS cli so these entries 
   will be restored after a switch reload/reboot.

6) To start DirectFlow Assist from the EOS event-handler:
	conf
	 event-handler directflow_assist
	  trigger on-boot
	  delay 360
	  asynchronous
	  action bash assist setup_start

   This will ensure that DFA is always running and restart it after a switch
   reload/reboot.  Delay time allows any MLAGS to become active (default mlag
   reload-delay is 300 seconds).

   To start DFA from bash for testing: assist start

7) Monitor the DFA log file via:  
   tail -f /var/log/directflow_assist.log

8) From bash use the assist commands from bash to check status of the 
   DFA process, monitor flows or delete dynamic DFA flows. Examples:
   assist status
   assist monitor

9) To stop the DFA process from bash enter:
   assist stop


Additional Information:
------------------------

* Four modes of operation are supported:
	SHUNT_MODE     by default traffic goes through firewall 
	INLINE_MODE    upstream traffic flows from the switch to the firewall
	                       and then to the downstream network, drops can be 
	                       installed to block attacks originating upstream 
	MIRROR_MODE    traffic bypasses firewall, drops only

  The active operating mode is set by the configuration variable: 
	OPERATING_MODE

  The shipping default is SHUNT_MODE.  In this mode all traffic flows 
  through the firewall until a firewall policy explicitly requests assistance 
  for specific flows to bypass or be dropped at the switch.

  To use Tap Mode for drops only (i.e. no redirects) set mode to MIRROR_MODE

* DFA will only accept connections from source IP addresses configured in
ACCEPT_SYSLOG_MSGS_FROM_IP defined in config.py

* If firewall is configured to pass Spanning Tree BPDUs you must disable 
   spanning tree on vlans on trunks going through the firewall.
   - if/when spanning tree is not runing on vlans configured through the firewall
   	 be careful to not remove the STATIC_PORT_BINDING flows or disable directflow 
   - be careful to keep STATIC_PORT_BINDING flows in place if manually deleting
     DROP or BYPASS flows
   - consider using the EOS storm-control feature

* Carefully check allowed vlans and tagging of the native vlan on trunks links to
  the firewall during initial config.

* DirectFlow flow entry aging timers for both max. lifetime and idle time defaults
can be changed in the configuration files (config_common.py, config.py).
Alternatively the max. lifetime for a flow entry added for a specific firewall 
policy can be configured with the policy name on the firewall. If the policy name
ends with the following character string '_ddm', where dd is an integer between
1 and 1440 that represents the number of minutes the flow entry should exist on
the switch. For example, policy name: backup_flow_bypass_60m 
will create a bypass flow on the switch that has a maximum lifetime of 60 minutes.
The idle timeout can be used to free up TCAM space for flow entries that aren't
matching any packets within the idle timeout interval.

* Time of day clocks on both the firewall and switch running DFA should use NTP
for synchronization.  Syslog message age is checked and old messages are
discarded. (see MAX_SYSLOG_MSG_AGE in config.py)

* Configure firewall to send syslog messages to  DirectFlow Assist for policies
that the switch should provide BYPASS or DROP "assistance" for.  If the firewall
does not provide fine grained control over which messages are sent it is possible
to use the DFA_IGNORE action in the DFA config file to filter syslog messages.

* When changing a security policy on the firewall, any currently 
assisted/offloaded flows in the switch must either be manually removed or 
allowed to timeout before the new policy will take effect.

* If you see host flapping warnings in the EOS /var/log/messages log file,
  verify that 'no switchport mac address learning' is configured on all
  interfaces or port-channels connected to the firewalls 

* Flow match criteria are specified in config.py.  Standard 5-tuple source
  and destination IP address, source and destination transport layer ports
  and protocol fields may be used.  IP addresses of 0.0.0.0 or transport layer
  ports equal to 0 in syslog message fields will not be used for flow matching.

* When running in a high availability deployment with two switches, two firewalls
 and MLAGS ensure that DFA is always running on both switches so that the active
 firewall is bypassed symmetrically or sees both directional flows for each
 network connection. If DFA is not running on one of the switches and the MLAG
 hash sends only one direction of a new TCP connection through the firewall the
 firewall will drop the connection since it won't see both SYN and SYN-ACK.
 
Approximate TCAM flow capabilities by switch platform:
 7050X (Trident2)  ~1500 L3 flow entries = 1500 drops or 750 bypass connections
 7050  (Trident+)   ~750 L3 flow entries =  750 drops or 375 bypass connections

Please contact bdebolle@arista.com with any comments or questions.

--------------------------------------------------------------------------------
Fortinet Firewall Specific Information:

* ensure 'set logtraffic-start enable ' is set for policies that will be used
   to trigger bypasses

=
