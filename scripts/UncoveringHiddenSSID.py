#!/usr/bin/python
# source: https://www.youtube.com/watch?v=_OpmfE43AiQ

import socket
from scapy.all import *

hidden_ssid_aps = set()

# Checking if we put all the argument
if len(sys.argv) != 2:
    print("Please add arguments to use the script")
    print("1 argument: Interface")
    exit()


def PacketHandler(pkt):
    if pkt.haslayer(Dot11Beacon):
        if not pkt.info:
            if pkt.addr3 not in hidden_ssid_aps:
                hidden_ssid_aps.add(pkt.addr3)
                print ("HIDDEN SSID: " + pkt.addr3)


sniff(iface = sys.argv[1], prn = PacketHandler)