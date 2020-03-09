from scapy.all import *
import argparse

# Inspiration : https://www.datacamp.com/community/tutorials/argument-parsing-in-python
# Construct the argument parser
ap = argparse.ArgumentParser()

# Add the arguments to the parser
ap.add_argument("-i", "--interface", required=True,
   help="Interface to use")
args = vars(ap.parse_args())

def packet_handler(packet):
    if packet.haslayer(Dot11ProbeReq):
        print(packet.info, " : ", packet.getlayer(Dot11).addr2.upper(), " : ", packet.getlayer(Dot11).addr1.upper())


sniff(iface=args['interface'], prn=packet_handler)