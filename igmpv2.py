# Envia 99 paquetes IGMPv2 con IP origen 192.168.1.42
# (c) hackingyseguridad.com 2018
# https://github.com/levigross/Scapy/blob/master/scapy/contrib/igmp.py
#    The function adjusts the IP header based on conformance rules 
#    and the group address encoded in the IGMP message.
#    The rules are:
#    1. Send General Group Query to 224.0.0.1 (all systems)
#    2. Send Leave Group to 224.0.0.2 (all routers)
#    3a.Otherwise send the packet to the group address
#    3b.Send reports/joins to the group address
#!/usr/bin/env python
from scapy.all import *
from scapy.contrib.igmp import IGMP
eth = Ether()

# Send General Group Query to 224.0.0.1 (all systems)
iph = IP(src='192.168.1.1', dst='224.0.0.1', proto=2)
igmp = IGMP(type=0x11, gaddr='0.0.0.0', mrtime=20)
igmp.igmpize(iph,eth)
sendp(eth/iph/igmp, iface="eth1", count=1)

# Send Leave Group to 224.0.0.2 (all routers)
iph = IP(src='192.168.1.42', dst='224.0.0.2', proto=2)
igmp = IGMP(type=0x17, gaddr='239.0.0.58', mrtime=20)
igmp.igmpize(iph,eth)
sendp(eth/iph/igmp, iface="eth1", count=1)

# Send reports/joins to the group address
iph = IP(src='192.168.1.42', dst='239.0.0.59', proto=2)
igmp = IGMP(type=0x16, gaddr='239.0.0.59', mrtime=20)
igmp.igmpize(iph,eth)
sendp(eth/iph/igmp, iface="eth1", count=1)
