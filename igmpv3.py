# Envio de 99 paquetes IGMPv3
#!/usr/bin/env python
from scapy.all import *
from scapy.contrib.igmp import IGMP

class IGMP3(Packet):
    name = "IGMP3"
    fields_desc = [ ByteField("type", 0x11),
                    ByteField("mrtime", 20),
                  XShortField("chksum", None),
                      IPField("gaddr", "0.0.0.0"),
                     IntField("others", 0x0)]
    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
        return p
bind_layers( IP, IGMP3, frag=0, proto=2)
p = IP(dst="192.168.1.252")/IGMP3()
send(p, count 99)
