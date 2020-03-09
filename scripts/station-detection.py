#  -*- coding: utf-8 -*-

# SWI - Labo2-MAC2
# Date: 09.03.2020
# File: station-detection.py
# Students: Stefan Dejanovic, Nathanael Mizutani

# Sources: - IEEE Std 802.11-2016
#          - https://gist.github.com/securitytube/5291959

from scapy.all import *

# Probe request subtype -> 0100
if len(sys.argv) != 2:
    print("usage : station-detection.py <interface>")
    exit()

interface = sys.argv[1]

def PacketHandler(pkt) :

  if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 4 :
			if pkt.addr2 not in ap_list :
				#ap_list.append(pkt.addr2)
				print "AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)


sniff(iface=interface, prn = PacketHandler)