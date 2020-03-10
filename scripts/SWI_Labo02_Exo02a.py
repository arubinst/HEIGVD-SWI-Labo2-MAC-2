# Source:
#
# Author: Victor Truan, Jerome Bagnoud | SWI - Labo 02 - Exo 02a

import argparse
from scapy.all import *

STA_SET = set({})

# Arguments
parser = argparse.ArgumentParser(description="Ce script permet d'afficher les STA qui cherche activement un SSID passe en argument")
parser.add_argument("-i", "--interface", required=True, help="l'interface a utiliser")
parser.add_argument("--ssid", required=True, type=str, help="le SSID a rechercher")

arguments = parser.parse_args()

def handlePacket(packet):
    # On regarde les Probe request
    if(packet.type == 0 and packet.subtype == 4):
        # Si le SSID du packet correspond au SSID donne
        if(packet.info.decode() == arguments.ssid):
            # On l'ajoute dans l'ensemble et on l'affiche
            if(packet.addr2 not in STA_SET):
                print("[+] " + packet.addr2)
                STA_SET.add(packet.addr2)

# On commence a sniffer, chaque packet collecte est envoye a la fonction handlePacket
print("STAs recherchant " + arguments.ssid + "\n")
a = sniff(iface=arguments.interface, prn=handlePacket)