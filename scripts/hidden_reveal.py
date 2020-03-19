#!/usr/bin/env python

#sources:
# https://www.pentesteracademy.com/video?id=471
# https://www.shellvoide.com/python/how-to-code-a-simple-wireless-sniffer-in-python/
# https://www.acrylicwifi.com/en/blog/hidden-ssid-wifi-how-to-know-name-of-network-without-ssid/

from scapy.all import *

hidden_ssids = []
interface = "wlan0mon"

def PacketHandler(pkt) :
	# On regarde si les packets proviennent d'une AP et on rempli le tableau des AP trouvees pour les faire correspondre par la suite
	if pkt.haslayer(Dot11Beacon) :
		# on verifie qu'on ne met pas deux fois un beacon provenant de la meme AP et que le nom de l'AP soit cachee pour la mettre dans la liste
		if len(pkt.info) == 0 or pkt.getlayer(Dot11Elt).ID == 0:
			if pkt.addr3 not in hidden_ssids :
				print "New Hidden MAC found : %s" %(str(pkt.addr3))
				hidden_ssids.append(pkt.addr3)
	elif pkt.haslayer(Dot11ProbeResp) :
		# print "Probe Response found"
		if pkt.getlayer(Dot11).addr3 in hidden_ssids :
			print "Hidden AP reveal : %s on MAC : %s" %(pkt.info.decode("utf-8"), str(pkt.addr3))

# we start sniffing packets on interface wlan0mon, it must first be activated with sudo airmon-ng start wlan0
sniff(iface=interface, prn = PacketHandler, count=200)

