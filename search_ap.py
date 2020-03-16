#!/usr/bin/env python

# Sources :
# - https://gist.github.com/securitytube/5291959
# - https://www.thepythoncode.com/article/create-fake-access-points-scapy

from scapy.all import *
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

iface = "wlp0s20u1"

sta_list = {}

def PacketHandler(packet):
    #Capture if toDS and fromDS is 0 and if a new STA / AP association
    if packet.haslayer(Dot11Elt)\
        and packet.FCfield & 0x1 == 0 \
        and packet.FCfield & 0x2 == 0 \
        and str(packet.addr3) != "ff:ff:ff:ff:ff:ff" \
        and (packet.addr2 not in sta_list or packet.addr3 not in sta_list[packet.addr2]):
        try:
            sta = packet.addr2 if packet.addr2 != packet.addr3 else packet.addr1
            bssid = packet.addr3

            # Store for remove duplicate
            if sta in sta_list:
                sta_list[sta].append(bssid)
            else: #first found
                sta_list[sta] = [bssid]

            print("%s\t %s" % (sta, bssid))
        except Exception as e:
            print(e)
            return

# Sniff phase
print("Press CTRL+C whenever you're happy with the APs list.")
print("SPA\t\t\t AP")
sniff(iface=iface, prn=PacketHandler)
