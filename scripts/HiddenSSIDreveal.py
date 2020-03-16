#!/usr/bin/python
# SWI - Labo1-MAC2
# Date: 15.03.2020
# File: HiddenSSIDreveal.py
# Students: Stefan Dejanovic, Nathanael Mizutani
# source: https://www.youtube.com/watch?v=_OpmfE43AiQ

from scapy.all import *

hidden_ssid_aps = set()

# Checking if we put all the argument
if len(sys.argv) != 2:
    print("Please add arguments to use the script")
    print("1 argument: Interface")
    exit()


def PacketHandler(pkt):

    # To get the ssid we check the prob response and check that the address is on our array
    if ( pkt.type == 0 ) and ( pkt.subtype == 5 ) and ( pkt.addr3 in hidden_ssid_aps ):
        print ("HIDDEN SSID Uncovered:" + str(pkt.info) + " " + str(pkt.addr3))

    # if it's a beacon
    elif pkt.haslayer(Dot11Beacon):
        # if we don't have the SSID
        if len(pkt.info.decode()) == 0:
            print("pkt.addr3" + pkt.addr3)
            # get the address if not in the array hidden_ssid_aps
            if pkt.addr3 not in hidden_ssid_aps:
                hidden_ssid_aps.add(pkt.addr3)
                print ("HIDDEN BSSID: " + pkt.addr3)

if __name__ == "__main__":
    sniff(iface = sys.argv[1], prn = PacketHandler)