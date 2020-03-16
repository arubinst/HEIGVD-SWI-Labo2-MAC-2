
from scapy.all import *
import argparse

parser = argparse.ArgumentParser(prog="Scapy hidden SSID reveal",
                                 usage="python3 hiddenAP.py -i wlan0mon",
                                 description="Scapy based wifi reveal")
parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")

args = parser.parse_args()

iface = args.Interface
bssid_found = {}

def find_ssid_searched(packet):
    if Dot11Elt in packet: 
        # On connait deja cette adresse mais on avait pas le SSID correspondant
        if Dot11ProbeResp in packet and packet.addr3 in bssid_found:
            # On ajoute le SSID a l'adresse
            bssid_found[packet.addr3] = packet.info.decode("utf-8")

        elif Dot11Beacon in packet and packet.info.decode("utf-8") == '' and packet.addr3 not in bssid_found: 
            # We don't have the SSID yet
            bssid_found[packet.addr3] = "Unknown"


print("Searching hidden SSID, please wait 15 seconds...")
sniff(iface=iface, prn=find_ssid_searched, timeout=15)

for ssid in bssid_found:
    print("{} {}".format(ssid, bssid_found[ssid]))
