#!/usr/bin/env python

from scapy.all import *

interface = "wlan0mon"

net_topo = {}
ssid_mac_map = {}

def packetHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0:

            # get packet infos
            ssid = pkt.info
            mac = pkt.addr2

            # handle AP beacons
            if pkt.subtype == 8:
                if ssid not in net_topo:
                    net_topo[ssid] = {}
                    ssid_mac_map[ssid] = mac

                    print("AP : {} with MAC {}".format(ssid, mac))

            # handle STA probe requests
            elif pkt.subtype == 4:
                if ssid in net_topo:
                    net_topo[ssid].add(mac)

                    print("STA : {} with MAC {}".format(ssid, mac))

# we sniff packets for a while to
sniff(iface=interface, prn = packetHandler, count=200)

# print results
print("STAs             APs")
for ssid in net_topo:
    # get the mac address from the ssid
    ap_mac = ssid_mac_map[ssid]
    # show clients
    for client_mac in net_topo[ssid]:
        print("{}       {}".format(client_mac, ap_mac))

