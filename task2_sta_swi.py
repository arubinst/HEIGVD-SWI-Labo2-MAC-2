#!/usr/bin/env python3
# Julien Huguet & Antoine Hunkeler

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap
from scapy.sendrecv import sniff


interface = "wlan0mon"
sta_list = []

ssid_target = input("Please enter an ssid to target : ")

def getSTAList(packet):
	if Dot11ProbeResp in packet and Dot11Elt in packet[Dot11ProbeResp] and packet.info.decode('utf-8')  == ssid_target and packet.addr2 not in sta_list:	
		ssid = packet.info
		sta = packet.addr2
		sta_list.append(sta)
		print("| SSID : %s | STA : %s |" % (ssid , sta))


#Sniff the different AP and print for user
sniff(iface=interface, prn=getSTAList)
print("Sta : %s" % (sta_list))
