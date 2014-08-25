#!/usr/bin/env python

import dpkt

f = open('vscommand.cap')
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    #check whether IP packets: to consider only IP packets 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
            continue
            #skip if it is not an IP packets 
    ip=eth.data
    if ip.p==dpkt.ip.IP_PROTO_TCP: #Check for TCP packets
           tcp=ip.data 
           #ADD TCP packets Analysis code here
           if tcp.dport == 9999:
		       print str(tcp.data)
           elif tcp.sport == 9999:

		       print str(tcp.data)


f.close()
