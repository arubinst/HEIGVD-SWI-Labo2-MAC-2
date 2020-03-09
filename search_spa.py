#!/usr/bin/env python

# Sources :
# - https://gist.github.com/securitytube/5291959
# - https://www.thepythoncode.com/article/create-fake-access-points-scapy

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap, Dot11ProbeResp
from scapy.sendrecv import sniff

iface = "wlp0s20u1"
target_ssid = ""

if len(sys.argv) == 2: # Demand number of fake SSID
    target_ssid = sys.argv[1]
else: # Reading file spliting every '\n'
    print("%s <ssid to filter>" % sys.argv[0])
    exit(-1)

sta_list = []

def PacketHandler(packet):
    if Dot11ProbeResp in packet \
            and Dot11Elt in packet[Dot11ProbeResp] \
            and packet[Dot11ProbeResp][Dot11Elt].ID == 0 \
            and packet.info == target_ssid \
            and packet.addr2 not in sta_list:
        try:
            sta = packet.addr2
            ssid_wanted = packet.info
            intensity = packet.dBm_AntSignal
            sta_list.append(sta)
            print("=== Target #%d ===\nsta: %s, ssid wanted: %s, intensity: %d dBm" % (
                len(sta_list), sta, ssid_wanted, intensity))
        except Exception as e:
            print(e)
            return

# Sniff phase
print("Press CTRL+C whenever you're happy with the STAs list.")
sniff(iface=iface, prn=PacketHandler)
