# Source:
#
# Author: Victor Truan, Jerome Bagnoud | SWI - Labo 02 - Exo 02a

import argparse
from scapy.all import *

BROADCAST_MAC_ADDRESS = "FF:FF:FF:FF:FF:FF"
STA_SET = set({})

# Arguments
parser = argparse.ArgumentParser(description="")
parser.add_argument("-i", "--interface", required=True, help="l'interface a utilise")
parser.add_argument("--ssid", required=True, type=str, help="le SSID a recherche")

arguments = parser.parse_args()

def handlePacket(packet):
    if(packet.type == 0 and packet.subtype == 4):
        if(packet.info.decode() == arguments.ssid):
            if(packet.addr2 not in STA_SET):
                print("[+] " + packet.addr2)
                STA_SET.add(packet.addr2)

# Begin to sniff, passing every packet collected to the packetHandling function
a = sniff(iface=arguments.interface, prn=handlePacket)