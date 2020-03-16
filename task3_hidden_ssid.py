#!/usr/bin/env python3
# Julien Huguet & Antoine Hunkeler
# Source : https://www.youtube.com/watch?v=_OpmfE43AiQ

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap
from scapy.sendrecv import sniff


interface = "wlan0mon"
hidden_ssid = set()

def getHiddenSSID(packet):
	# Check if there is beacon packet
	if packet.haslayer(Dot11Beacon):	
		# Check if there is no ssid name
		if not packet.info:
			# Remove dupplicate entry
			if packet.addr3 not in hidden_ssid:
				hidden_ssid.append(packet.addr3)
	# Check if packet have a probe response and if the BSSID address is on the list to get the SSID in the probe response
	elif packet.haslayer(Dot11ProbeResp) and (packet.addr3 in hidden_ssid):
		print("Hidden SSID : %s" % (packet.info))
			

		


#Sniff to find hidden ssid
sniff(iface=interface, prn=getHiddenSSID)

