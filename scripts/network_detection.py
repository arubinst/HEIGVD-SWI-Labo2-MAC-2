#!/usr/bin/env python

from scapy.all import *

interface = "wlp2s0mon"

net_topo = {}

def packetHandler(pkt):
    if pkt.haslayer(Dot11):
        # Management type
        if pkt.type == 0:

            # handle AP beacons
            if pkt.subtype == 8:

                # get packet infos
                ssid = pkt.info
                mac = pkt.addr2

                if ssid not in net_topo:
                    net_topo[mac] = {}

                    print("found AP : {} with MAC {}".format(ssid, mac))
        # Data type
        elif pkt.type == 2:

            # get packet infos
            src_mac = pkt.addr1
            ap_mac = pkt.addr3

            if ap_mac in net_topo:
                net_topo[ap_mac].add(src_mac)
            else:
                net_topo[ap_mac] = {src_mac}



# we start sniffing the packets
sniff(iface=interface, prn = packetHandler, count=200)

# print results
print("STAs             APs")
for ap_mac in net_topo:
    # show clients
    for client_mac in net_topo[ap_mac]:
        print("{}       {}".format(client_mac, ap_mac))

