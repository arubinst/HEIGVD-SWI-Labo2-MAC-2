# Python 3.7.6
# 
# Auteurs: Adrien Barth, Lionel Burgbacher
# Date:    16.03.2020
# Source:  https://www.shellvoide.com/python/finding-connected-stations-of-access-point-python-scapy/
# 
# Description:
# Développer un script en Python/Scapy capable de générer une liste d'AP visibles
# dans la salle et de STA détectés et déterminer quelle STA est associée à quel AP.
# 

import argparse
from scapy.all import *
from threading import Event

parser = argparse.ArgumentParser(description='SWI-Lab-02-Detect-Clients+APs')
parser.add_argument("-i", "--iface", default="wlan0mon", help="Interface used for the attack.")
args = parser.parse_args()

AP_LIST = set()

'''
Callback function whenever a packet has been sniffed by Scapy.
Search for data frames
'''
def findApWithSta(packet):
	'''
	Here we maintain a list of APs
	'''
	if packet.haslayer(Dot11Beacon) and packet.getlayer(Dot11).addr2 not in AP_LIST:
			AP_LIST.add(packet.getlayer(Dot11).addr2)
			print("New access point found with MAC address " + packet.addr2)
	

	'''
	Here we filter for 802.11 packet of type 2 (data frames)
	'''
	if packet.haslayer(Dot11FCS) and packet.getlayer(Dot11FCS).type == 2:
		'''
		Here we define which one is the AP or the STA
		'''
		STA_MAC = ''
		AP_MAC = ''
		if packet.addr2 in AP_LIST:
			AP_MAC = packet.addr2
			STA_MAC = packet.addr1
		elif packet.addr1 in AP_LIST:
			AP_MAC = packet.addr1
			STA_MAC = packet.addr2

		if STA_MAC != '' and STA_MAC != 'ff:ff:ff:ff:ff:ff' and AP_MAC != '':
			print("STA " + STA_MAC + " is connected to AP " + AP_MAC)


print("Searching for APs and connected STA")

# Sniffing packets
sniff(iface=args.iface, prn=findApWithSta)
Event().wait()