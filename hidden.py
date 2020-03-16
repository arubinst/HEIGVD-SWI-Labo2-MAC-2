#!/usr/bin/env python

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap
from scapy.sendrecv import sniff

iface = "wlp0s20u1"

ap_list = []
ap_bssidToSsid = {}

def inputNumber(message, imin, imax):
    while True:
        try:
            userInput = int(input(message))
        except ValueError:
            print("Not an integer! Try again.")
            continue
        else:
            if imin > userInput or userInput > imax:
                continue
            return userInput
            break

def PacketHandler(packet):
    # Filter all beacon
    if packet.haslayer(Dot11Beacon) and packet.getlayer(Dot11).addr3 not in ap_list:
        # if no ssid or empty ssid
        if packet.getlayer(Dot11Elt).info.decode("utf-8") == '' or packet.getlayer(Dot11Elt).ID != 0:
            # this is a hidden network
            print("Hidden Network Detected (BSSID: %s)" % packet.getlayer(Dot11).addr3)
            ap_list.append(packet.getlayer(Dot11).addr3)
            # if we already saw a probe response from this bssid
            if packet.getlayer(Dot11).addr3 in ap_bssidToSsid:
                # we found an association
                print("Corresponding SSID found!")
                print("\tBSSID: %s\tSSID: %s" % (packet.getlayer(Dot11).addr3, packet.getlayer(Dot11Elt).info.decode("utf-8")))
    # Filter all probe response
    if packet.haslayer(Dot11ProbeResp) and packet.getlayer(Dot11).addr3 not in ap_bssidToSsid:
        ap_bssidToSsid[packet.getlayer(Dot11).addr3] = packet.getlayer(Dot11Elt).info
        # if we previously detected an ap with this ssid
        if packet.getlayer(Dot11).addr3 in ap_list:
            # we found an association
            print("Corresponding SSID found!")
            print("\tBSSID: %s\tSSID: %s" % (packet.getlayer(Dot11).addr3, packet.getlayer(Dot11Elt).info.decode("utf-8")))

print("Searching for suspicious beacon frames and corresponding probe responses...")
sniff(iface=iface, prn=PacketHandler)

