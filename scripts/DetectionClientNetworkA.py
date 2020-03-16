# SWI - Labo1-MAC2
# Date: 28.02.2020
# File: DetectionClientNetworkA.py
# Students: Stefan Dejanovic, Nathanael Mizutani
# source: https://security.stackexchange.com/questions/130590/sending-probe-request-frames-receving-probe-response-scapy

from scapy.all import *

Client_Find = []

# Checking if we put all the argument
if len(sys.argv) != 3:
    print("Please add arguments to use the script")
    print("1 argument: BSSID")
    print("2 argument: Interface")
    exit()

def pkt_callback(pkt):
    # Check if is type 0 and subtype 4 for prob request
    # Check if it's the same SSID as given in parameter
    if ( pkt.getlayer(Dot11).type == 0 ) and  ( pkt.getlayer(Dot11).subtype == 4 ) and ( pkt.info.decode() == sys.argv[1]):
        # if not already shown, print it
        if (pkt.getlayer(Dot11).addr2 not in Client_Find):
            print("Client : " + str(pkt.getlayer(Dot11).addr2))
            # Add to the array
            Client_Find.append(pkt.getlayer(Dot11).addr2)

if __name__ == "__main__":
    print("SSID : " + sys.argv[1])
    sniff(iface=sys.argv[2], prn=pkt_callback)