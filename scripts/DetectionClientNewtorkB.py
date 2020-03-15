# SWI - Labo1-MAC2
# Date: 28.02.2020
# File: FindSTAfromSSID.py
# Students: Stefan Dejanovic, Nathanael Mizutani
# source: https://www.shellvoide.com/python/finding-connected-stations-of-access-point-python-scapy/

# -*- coding: utf-8 -*-

from scapy.all import *

APs = []

def pkt_callback(pkt):
    if pkt.haslayer(Dot11Beacon):
        bss = pkt.getlayer(Dot11).addr2.upper()
        if bss not in APs:
            APs.append(bss)

    elif pkt.getlayer(Dot11).type == 2:
        # This means it's data frame.
        sn = pkt.getlayer(Dot11).addr2.upper()
        rc = pkt.getlayer(Dot11).addr1.upper()

        if sn in APs:
            print ("AP (" + sn + ") > STA (" + rc + ")" )
        elif rc in APs:
             print ("AP (" + rc + ") < STA (" + sn + ")" )

if __name__ == "__main__":
    sniff(iface="wlx00c0ca6aac0a", prn=pkt_callback)