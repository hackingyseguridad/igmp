from scapy.all import *
import igmp_scapy
from igmp_scapy import *
import ipaddr
import sys

numgrp = int(sys.argv[1])

pkt = Ether(dst="01:00:5E:00:00:16",src="00:00:60:02:00:01",type=0x800)
pkt = pkt/ IP(ttl=1,proto="igmp",src="4.0.0.100",dst="224.0.0.22")
pkt = pkt /IGMPv3(type="Version 3 Membership Report",numgrp=numgrp)

#maddr = ipaddr.IPv4Address('232.1.1.0')
for step in range(1,numgrp+1):
   maddr = ipaddr.IPv4Address('232.1.1.0') + step
   maddr_str = str(maddr)
   print maddr_str
   pkt = pkt / IGMPv3gr(rtype="Mode Is Include", numsrc=2,maddr=maddr_str, srcaddrs=['2.0.0.100', '1.0.0.100'])

print pkt.show()

sendp(pkt,iface='eth4',count=5,inter=0.2,verbose=True)
