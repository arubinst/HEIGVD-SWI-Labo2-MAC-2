# Python 3.7.6
# 
# Auteurs: Adrien Barth, Lionel Burgbacher
# Date:    16.03.2020
# 
# Description:
# Développer un script en Python/Scapy capable de lister
# toutes les STA qui cherchent activement un SSID donné
#

import argparse
from datetime import datetime
from scapy.all import *
from threading import Event

parser = argparse.ArgumentParser(description='SWI-Lab-02-Detect-Clients')
parser.add_argument("-i", "--iface", default="wlan0mon", help="Interface used for the attack.")
parser.add_argument("-S", "--SSID", required=True, help="SSID for which are sniffing probe request.")
args = parser.parse_args()

MAC = set()

'''
Callback function whenever a packet has been sniffed by Scapy.
Search for Probe-Request
'''
def checkForProbeRequest(packet):
	'''
	We are looking for 802.11 packet with the following type/subtype:
	- Type 0    = Management frames
	- Subtype 4 = Probe-Request
	'''
	if packet.type == 0 and packet.subtype == 4:
		'''
		The SSID can be found in the info field of the Scapy packet.
		If this is the SSID we're looking for, we add the MAC address of
		the devices in the list and print it.
		'''
		if str(packet.info)[2:-1] == args.SSID and packet.addr2 not in MAC:
			MAC.add(packet.addr2)
			print("Found a new device! MAC is " + packet.addr2)


print("Searching for devices sending probe request for SSID " + args.SSID)

# Sniffing packets
sniff(iface=args.iface, prn=checkForProbeRequest)
Event().wait()