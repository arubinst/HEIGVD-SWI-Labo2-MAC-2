# Source:
#
# Author: Victor Truan, Jerome Bagnoud | SWI - Labo 02 - Exo 02b

import argparse
from scapy.all import *

BROADCAST_MAC_ADDRESS = "ff:ff:ff:ff:ff:ff"
PAIR_SET = set(tuple())

# Arguments
parser = argparse.ArgumentParser(description="Ce script permet d'afficher les d'afficher les STAs presentent dans la zone ainsi que l'AP auxquelles elles sont associe")
parser.add_argument("-i", "--interface", required=True, help="l'interface a utiliser")

arguments = parser.parse_args()

def handlePacket(packet):
    # Si c'est un packet de Data (type 2)
    if(packet.type == 2):
        tmp = (packet.addr1, packet.addr2)
        # On filtre les adresses de Broadcast
        if(tmp not in PAIR_SET and packet.addr1 != BROADCAST_MAC_ADDRESS):
            print(tmp[0] + " \t\t " + tmp[1])
            PAIR_SET.add(tmp)

print("STAs\t\t\t\t APs\n")

# On commence a sniffer, chaque packet collecte est envoye a la fonction handlePacket
a = sniff(iface=arguments.interface, prn=handlePacket)