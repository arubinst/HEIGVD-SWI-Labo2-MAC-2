# Python 3.7.6
#
# Auteurs: Adrien Barth, Lionel Burgbacher
# Date:    16.03.2020
# Source:  https://www.youtube.com/watch?v=_OpmfE43AiQ
#
# Description:
# Ce script permet de découvrir les SSID correspondant à un réseau configuré comme étant "invisible".

import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp

parser = argparse.ArgumentParser(description='Hidden SSID Reveal')

#L'interface par défaut est wlan0mon
parser.add_argument("-i", "--interface", default="wlan0mon", help="Interface you want to scan")
args = parser.parse_args()

#Liste des SSID cachés
hidden_ssid_aps = set()

def packethandler(pkt):

    if pkt.haslayer(Dot11Beacon):
        #On regarde ici si le SSID est NULL pour ajouter l'adresse ensuite au set
        if not pkt.info:
            if pkt.addr3 not in hidden_ssid_aps:
                hidden_ssid_aps.add(pkt.addr3)
                print("Hidden SSID Netwrok Found! BSSID: ", pkt.addr3)
    #On regarde si l'adresse est dans le set, si elle y est, on peut retrouver le SSID
    elif pkt.haslayer(Dot11ProbeResp) and pkt.addr3 in hidden_ssid_aps:
        print("Hidden SSID Uncovered!" + pkt.info.decode())


print("In progress...")
# Permet d'analyser les paquets, le timeout est arbitraire
sniff(iface=args.interface, prn=packethandler, timeout=10)
