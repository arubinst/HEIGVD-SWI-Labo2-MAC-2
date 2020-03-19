#!/usr/bin/env python

from scapy.all import *
import sys

interface = "wlan0mon"

searched_ssid = "default_ssid"

sta_set = set()

def packetHandler(pkt):
    if pkt.haslayer(Dot11):
        # Management type
        if pkt.type == 0:

            # handle AP beacons
            if pkt.subtype == 4:

                # get packet infos
                ssid = pkt.info
                mac = pkt.addr2

                print("STA {} looking for {}".format(mac, ssid))
                if ssid == searched_ssid:
                    sta_set.add(mac)

if len(sys.argv) - 1 == 1:
    searched_ssid = sys.argv[1]

    # we start sniffing the packets
    sniff(iface=interface, prn = packetHandler, count=2000)

    # show list of STAs looking for the ssid
    print("STAs looking for {} :".format(searched_ssid))
    print("-------------------------------")
    for client in sta_set:
        print(client)

else:
    print("please provide an SSID as argument")

