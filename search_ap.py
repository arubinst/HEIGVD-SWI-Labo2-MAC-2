#!/usr/bin/env python

# Sources :
# - https://gist.github.com/securitytube/5291959
# - https://www.thepythoncode.com/article/create-fake-access-points-scapy

from scapy.all import *
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

iface = "en0"

sta_list = {}

def PacketHandler(packet):
    #Capture if toDS and fromDS is 0 and if a new STA / AP association
    if Dot11 in packet \
        and p.FCfield & 0x1 == 0 \
        and p.FCfield & 0x2 == 0 \
        and packet.addr2 not in sta_list \
        or packet.addr3 not in sta_list[packet.addr2]:

        try:
            sta = packet.addr2
            bssid = packet.addr3

            # Store for remove duplicate
            if sta in sta_list:
                sta_list[sta].append(bssid)
            else: #first found
                sta_list[sta] = [bssid]

            print("%s\t %s" % (
                len(sta_list), sta, ssid_wanted, intensity))
        except Exception as e:
            print(e)
            return

# Sniff phase
print("Press CTRL+C whenever you're happy with the APs list.")
print("SPA\t\t\t AP")
sniff(iface=iface, prn=PacketHandler)
