# SWI - Labo1-MAC2
# Date: 28.02.2020
# File: FindSTAfromSSID.py
# Students: Stefan Dejanovic, Nathanael Mizutani
# source: https://www.shellvoide.com/python/finding-connected-stations-of-access-point-python-scapy/

# -*- coding: utf-8 -*-

from scapy.all import *

# Checking if we put all the argument
if len(sys.argv) != 2:
    print("Please add arguments to use the script")
    print("1 argument: Interface")
    exit()

APs = []

def pkt_callback(pkt):
    # We get the beacon
    if pkt.haslayer(Dot11Beacon):
        # Add the BSSID to the Aps Array
        bss = pkt.getlayer(Dot11).addr2.upper()
        if bss not in APs:
            APs.append(bss)

    # type 2 means that there is a communication
    elif pkt.getlayer(Dot11).type == 2:
        # This means it's data frame.
        sn = pkt.getlayer(Dot11).addr2.upper()
        rc = pkt.getlayer(Dot11).addr1.upper()

        # Don't take the broadcast
        if sn != "FF:FF:FF:FF:FF:FF" and rc != "FF:FF:FF:FF:FF:FF":
            if rc in APs:
                print ("AP (" + rc + ") < STA (" + sn + ")" )
            #if sn in APs:
            #    print ("AP (" + sn + ") > STA (" + rc + ")" )

if __name__ == "__main__":
    print("Searching...")
    sniff(iface=sys.argv[1], prn=pkt_callback)