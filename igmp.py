#!/usr/bin/env python
from scapy.all import *
from scapy.contrib.igmp import IGMP

eth = Ether()
iph = IP(src='1.1.1.1', dst='224.0.0.1', proto=2)
igmp = IGMP(type=0x11, gaddr='0.0.0.0', mrtime=10)
igmp.igmpize(iph,eth)
sendp(eth/iph/igmp, iface="eth0", count=99)
