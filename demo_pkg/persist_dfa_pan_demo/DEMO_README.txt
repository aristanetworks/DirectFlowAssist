Arista Networks Inc.
DirectFlow Assist for PAN Firewall - Demo Notes 
-------------------------------------------------------------------------------

Devices:
 demo-linux1   (172.22.28.27)  demo/demo; ping target for backup elephant flow use case
 demo-linux2   (172.22.28.28)  demo/demo; ping target for DoS Attack use case
 bizdev-pan-5050 (172.22.28.35)  demo/demo
 directflow-7050    (172.22.28.95)
   ssh demo@directflow-7050    passwd=demo     EOS cli
   demo software at: /persist/sys/extensions/directflow_assist_pan
     to start: ./assist.py run_demo

Demo UI:  
 Freds web UI with realtime graph of port counters and start, stop, delete flows

 terminal window: ssh to directflow-7050: tail -f /var/log/directflow_assist_pan.log
   shows received PAN FW syslog msgs, extracted Flow Spec, cli config commands generated
 terminal window: ssh to directflow-7050: assist monitor  
     shows flow entries on switch

When demoing with pings (ICMP echo) there won't be any L4 ports in the 
directflow match criteria. 


Demo Sequence: 
Press: Pause
Press: Delete Flows
sudo ping -i .1 demo-linux1  to trigger FW Backup scenario
Show customer that all traffic is flowing through switch and firewall 
Press: Resume  to start DFA processing PAN FW syslog messages
Show DFA log messages and flow entries on switch for BYPASS flows

Press: Pause
Press: Delete Flows
sudo ping -i .1 demo-linux2  to trigger FW DoS Attack threshold
Show customer DoS Attack flowing through switch eth1 and firewall eth3 
 then being dropped at firewall 
Press: Resume  to start DirectFlow Assist processing PAN FW syslog messages
Show DFA log messages and flow entries on switch for DROP flow


After amazed customer places large purchase order for Arista switches with 
DirectFlow Assist, repeat with next customer!

----------------------------------------------------------------------------------------
Demo switch setup:

1) Install demo rpm:
switch# extension directflow_assist_pan-0.20.demo-1.noarch.rpm

DirectFlow-7050#show extensions detail 
       Name: directflow_assist_pan-0.20.demo-1.noarch.rpm
    Version: 0.20.demo
    Release: 1
   Presence: available 
     Status: installed 
     Vendor: Arista Networks, Inc. <bdebolle@arista.com>
    Summary: DirectFlow Assist for PAN Firewalls
       RPMS: directflow_assist_pan-0.20.demo-1.noarch.rpm 0.20.demo/1
 Total size: 165408 bytes
Description:

see: /mnt/flash/.extensions/

2) copy installed-extensions boot-extensions 

3) Setup event-handler in config mode:

event-handler directflow_assist_setup
   trigger on-boot
   action bash assist setup
   delay 30
   
event-handler directflow_assist_run_demo
   trigger on-boot
   action bash /usr/bin/immortalize --daemonize assist run_demo
   delay 60
   asynchronous

4) copy run start
