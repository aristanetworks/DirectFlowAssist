Arista Networks, Inc.
EOS Extension: DirectFlow Assist for Palo Alto Networks Firewalls
===============================================================================

Supported EOS versions: 4.14.7M, 4.14.8M
Supported Platforms: 7050 and 7050X Series
Minimum PAN-OS version: 6.1.0
Supported PAN deployment mode: virtual-wire
Supported OPERATING_MODEs: SHUNT_MODE, INLINE_MODE, MIRROR_MODE

-------------------------------------------------------------------------------
Installation and Operation:

1) Install extension from EOS cli:
  copy scp:user@server/path/directflow_assist_<name_and_version>.rpm extension:
  or
  copy http://server/path/directflow_assist_<name_and_version>.rpm extension:
  extension directflow_assist_<name_and_version>.rpm
  show extensions [detail]
  copy installed-extensions boot-extensions

  This will install the DirectFlow Assist python package at: 
  /usr/lib/python2.7/site-packages/directflow_assist

  the config file, README and LICENSE files at:
  /persist/sys/extensions/directflow_assist

  the startup script at:
  /usr/bin/assist

  a log rotation file at:
  /etc/logrotate.d/dfa_logrotate

  After running 'assist setup' a log file will be available at:
  /var/log/directflow_assist.log

  When DFA is running there will be a file that contains the process id at:
  /var/run/directflow_assist.pid

2) Enable eAPI for local unix domain sockets:
   conf
   management api http-commands
   no shutdown
   protocol unix-socket 
   end

   Verify config using: show management api http-commands 

3) Connect firewall interfaces to switch interfaces

4) Edit the DFA config file to define:
   - The interfaces used to connect the firewall.
     - for the firewall interfaces use the full interface name e.g. 'ethernet1/4'
   - IP address(es) of firewalls that this instance of DFA should process syslog
     messages from.  Syslog messages from any other IP address will be ignored. 
     - IP address(es) must be entered as string values in a python list, examples:
         ACCEPT_SYSLOG_MSGS_FROM_IP = ['1.1.1.1']
         ACCEPT_SYSLOG_MSGS_FROM_IP = ['1.1.1.1', '2.2.2.2']

   bash
   cd /persist/sys/extensions/directflow_assist
   sudo vi config.py
   Carefully input the interfaces and firewall IP address.

   * For SHUNT_MODE define all Zone A and B interfaces.
   * For INLINE_MODE only the Zone A interfaces are needed.
   * For MIRROR_MODE only SWITCH_INTERFACES_TO_FW_TAP and
     SWITCH_INTERFACES_TO_BE_MIRRORED interfaces are needed.

5) From bash:  assist setup 
   this will: create the static port-binding flows to send traffic through
              the attached firewall and create a log file at /var/log/

   IMPORTANT!: After the static flow entries have been created be sure to do
   a 'copy running-config startup-config' from the EOS cli so these entries 
   will be restored after a switch reload/reboot.

6) To start DFA from bash for testing enter: assist start

   To start DirectFlow Assist from an EOS event-handler for normal operation:
   conf
   event-handler directflow_assist
   trigger on-boot
   delay 360
   asynchronous
   action bash assist setup_start

   This will ensure that DFA is always running and restart it after a switch
   reload/reboot.  Delay time allows any MLAGS to become active (default mlag
   reload-delay is 300 seconds).

7) Monitor DFA activity:
   - via its log file:
     tail -f /var/log/directflow_assist.log

   - using assist commands:
 DirectFlow Assist - Command Line Processor:
 usage: assist <command> [options]

 Command            Description
 ------------------------------------------------------------------------
 start              Start DirectFlow Assist process
 stop               Stop DirectFlow Assist process
 status             Show multiple status elements for DFA
 monitor            Monitor active DirectFlow entries on switch
 delete             Delete DFA inserted DROP and BYPASS flows on switch
 setup              Initial setup of DFA static flows to/from the
                    attached firewall, create log file, etc.
 setup_start        Combined setup and start for cold starts from EOS
                    event-handler after reloads

8) Configure firewall to send syslog messages to DFA on port 9514 for UDP, TCP
or SSL/TLS connections.


Additional Information:
------------------------

* When 'assist setup' runs it installs STATIC_PORT_BINDING flows to direct traffic
through the attached firewall. For SHUNT_MODE setup also disables mac address 
learning and enables spanning tree bpdufilters as well as sets storm-control limits
on these interfaces.  Adjust limit rates if needed in your network environment.
  !! Be very careful to not remove the STATIC_PORT_BINDING flows or disable
  !! directflow when a firewall is attached to the switch creating a layer 2 loop.

* DFA must be restarted to use any changes in config.py made while it was running.

* Time of day clocks on both the firewall and switch running DFA should use NTP
for synchronization.  Syslog message age is checked and old messages are
discarded. (see MAX_SYSLOG_MSG_AGE in config.py)

* Configure firewall to send syslog messages to  DirectFlow Assist for policies
that the switch should provide BYPASS or DROP "assistance" for.  If the firewall
does not provide fine grained control over which messages are sent it is possible
to use the DFA_IGNORE action in the DFA config file to filter syslog messages.

* Carefully check allowed VLANs and tagging of the native VLAN on trunks links to
the firewall during initial config.

* DFA will only accept connections from source IP addresses configured in
ACCEPT_SYSLOG_MSGS_FROM_IP defined in config.py

* Operating Modes:
Three modes of operation are supported:
	SHUNT_MODE     by default traffic goes through firewall 
	MIRROR_MODE    traffic bypasses firewall, drops only
	INLINE_MODE    upstream traffic flows from the switch to the firewall and then to
	               the downstream network, drops can be installed to block attacks
	               originating upstream 

The active operating mode is set by the configuration variable:  OPERATING_MODE

The shipping default is SHUNT_MODE.  In this mode all traffic flows through the
firewall until a firewall policy explicitly requests assistance for specific flows
to bypass or be dropped at the switch.

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

* When changing a security policy on the firewall, any currently assisted/offloaded
flows in the switch must either be manually removed or allowed to timeout before the
new policy will take effect.

* If you see host flapping warnings in the EOS /var/log/messages log file, verify
that 'no switchport mac address learning' is configured on all interfaces or
port-channels connected to the firewalls.

* New triggers can be defined from syslog message fields using the 'trigger' field
of the DFA_CONTROLLER_SPEC in config.py.  See comments in config.py and existing
triggers for more info.

* Flow match criteria are specified in config.py in the 'flow_match' field of the
DFA_CONTROLLER_SPEC.  Standard 5-tuple source and destination IP address, source and
destination transport layer ports and protocol fields may be used.  IP addresses
of 0.0.0.0 and transport layer ports equal to 0 in syslog message fields will not be
used for flow matching.

* QoS Marking
For bypass flows DFA can set/mark Ethernet CoS and/or IP ToS fields
COS range <0-7>; TOS range <0-255>  uses the 6 most significant bits of this byte

Use COS_TOS_MARKING in config.py, key= app name from syslog msg, value is a dict with
key='COS' and/or 'TOS', value= integer; higher values = higher priority.  Example:
COS_TOS_MARKING = {
    'ssh': {'TOS': 16},
    'web-browsing': {'COS': 2},
    'ping': {'COS': 3, 'TOS': 8}}

* When running in a high availability deployment with two switches, two firewalls
and MLAGS links ensure that DFA is always running on both switches so that the
active firewall is bypassed symmetrically or sees both directional flows for each
network connection. If DFA is not running on one of the switches and the MLAG
hash sends only one direction of a new TCP connection through the firewall the
firewall will drop the connection since it won't see both SYN and SYN-ACK.
 
Approximate TCAM flow capabilities by Arista switch platform:
 7050X (Trident2)  ~1500 L3/4 flow entries = 1500 drops or 750 bypasses
 7050  (Trident+)   ~750 L3/4 flow entries =  750 drops or 375 bypasses

Extensions get placed into /mnt/flash/.extensions
Do not manually delete files in the .extensions directory.

--------------------------------------------------------------------------------
The DFA extension uninstall does NOT delete ssl certs etc from the 
/persist/sys/extensions/directflow_assist directory.

To remove an extension
1) Stop the process 'assist stop'
2) no extension xxxxx
3) del extension:
4) copy installed-extensions boot-extensions
5) Then install the upgrade as necessary

e.g.
sn411-alta-lab......02:57:41#no extension directflow_assist_pan-1.0.0.noarch.rpm
sn411-alta-lab......02:57:52#del extension:directflow_assist_pan-1.0.0.noarch.rpm
sn411-alta-lab......02:58:03#copy installed-extensions boot-extensions
Copy completed successfully.
sn411-alta-lab......02:58:11#sh extensions
Name                                       Version/Release           Status extension
------------------------------------------ ------------------------- ------ ----
CPU-Hist-1-3.swix                          1/3                       A, NI     1
EoSCliForSplunk-1.1.2.rpm                  1.1.2/1.fc14              A, I      1
GnuPlot-4.4.0.swix                         1.2.14/11.fc14            A, I     42
Telemetry-1.1.2.rpm                        1.1.2/1                   A, I      1
fping-2.4b2-10.fc12.i686.rpm               2.4b2/10.fc12             A, NI     1
splunkforwarder-6.2.2-255606.i386.rpm      6.2.2/255606              A, I      1

A: available | NA: not available | I: installed | NI: not installed | F: forced

--------------------------------------------------------------------------------
Palo Alto Networks Specific Information:

* DFA parses the default BSD format syslog messages from the PAN firewall

* The PAN firewall may send syslogs via UDP, TCP or TCP/SSL connections.
  - some notes to help choose a transport based on observed behaviors during
    testing:
    - UDP has the fastest response time but of course syslog messages can get lost
    - SSL is secure and reliable but if no syslog messages have been sent in
      several hours it appears that the firewall may not immediately send the next
      syslog message and it sometimes takes several messages to get queued at the
      firewall before they are sent
    - TCP response time has been good overall and may be the best choice in 
      environments that don't require an encrypted connection 
  - For SSL store the root certificate and DFA certificate and key files at the
    paths defined in config.py 
  - when installing the firewall certificates from the Certificate Management
    utility under the Device tab of the PAN web console.  Be sure to click the
    link with name of the certificate and enable the option "Certificate for 
    Secure Syslog"
  - SSL connections currently use TLSv1.0
  - DirectFlow Assist and the firewall must have certificates that are signed by
    the same trusted CA or self-signed certificate.
  - DFA is the server side of the SSL connection and needs a server certificate
    without a password.  The firewall uses a client certificate typically with a
    password on the SSL connection to DFA.

* On the firewall setup a Syslog Server Profile to the switches IP address and to 
the UDP, TCP or TCP/SSL port defined in the DirectFlow Assist config file.  Next 
setup a Log Forwarding object to that syslog server.  Then lastly, for any Security 
or DoS Protection Policy on the Action tab, check Log at Session Start and select 
the Log Forwarding object you created. 

* PAN Firewalls in a High Availability (HA) deployment:
  - only Active/Standby mode is supported
  - both firewalls must be running the same PAN-OS version be the same hardware model
  - Arista switch running DFA must be connected to same the interfaces on each
    firewall (e.g. ethernet1/1 and ethernet1/2) 

* If a subinterface is defined on the firewall interfaces then these are used to
qualify VLAN id when matching ingress traffic for bypasses.  Note: Threat drop
syslog messages currently do not provide subinterface/VLAN info so VLAN id is
not used to qualify the the drop flow entry.

* by default the PAN firewall maintains TCP connection state for 60 minutes. It is
also possible to define custom timeouts for individual applications.  If a connection
is being bypassed at the switch and the flow entry times out 
(see BYPASS_FLOW_LIFETIME) packets will then revert to traversing the firewall.   
 
=
