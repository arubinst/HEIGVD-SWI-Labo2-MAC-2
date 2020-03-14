#  -*- coding: utf-8 -*-

# SWI - Labo2-MAC2
# Date: 09.03.2020
# File: station-detection.py
# Students: Stefan Dejanovic, Nathanael Mizutani

# Sources: - IEEE Std 802.11-2016
#          - https://gist.github.com/securitytube/5291959

from scapy.all import *
import subprocess

# We check if the user provided the required numbers of arguments
if len(sys.argv) != 3:
    print("usage : station-detection.py <interface> <target ssid>")
    exit()

interface = sys.argv[1]
ssid = sys.argv[2]

found = False
wait_msg = "Scanning"

def PacketHandler(pkt):
	if pkt.haslayer(Dot11):
		# We check if it is a probe frame
		if pkt.type==0 and pkt.subtype==4:
			if ssid == pkt.info:
				target = pkt
				found = True
				
				print("SSID found!\nAP MAC: %s with SSID: %s " %(target.addr2, target.info))

print("Hit CRTL+C if you want to stop the script prematurely")

print(wait_msg)
sniff(iface=interface, prn = PacketHandler, store=0, timeout=2)

# The sniffing will repeat as long as the target is not found
while found == False:
	print(wait_msg))
	sniff(iface=interface, prn = PacketHandler, store=0, timeout=2)

subprocess.run("echo TEST", capture_output=True)