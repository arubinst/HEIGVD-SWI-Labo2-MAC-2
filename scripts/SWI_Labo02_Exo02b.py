# Source:
#
# Author: Victor Truan, Jerome Bagnoud | SWI - Labo 02 - Exo 02b

import argparse
from scapy.all import *

BROADCAST_MAC_ADDRESS = "ff:ff:ff:ff:ff:ff"
PAIR_SET = set(tuple())

# Arguments
parser = argparse.ArgumentParser(description="")
parser.add_argument("-i", "--interface", required=True, help="l'interface a utilise")

arguments = parser.parse_args()

def handlePacket(packet):
    if(packet.type == 2):
        tmp = (packet.addr1, packet.addr2)
        if(tmp not in PAIR_SET and packet.addr1 != BROADCAST_MAC_ADDRESS):
            print("[+] " + tmp[0] + " \t\t " + tmp[1])
            PAIR_SET.add(tmp)

print("STAs\t\t\t\t APs")
# Begin to sniff, passing every packet collected to the packetHandling function
a = sniff(iface=arguments.interface, prn=handlePacket)