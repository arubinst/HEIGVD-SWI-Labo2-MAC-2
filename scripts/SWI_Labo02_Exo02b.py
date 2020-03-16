# Source:
# - https://stackoverflow.com/questions/30811426/scapy-python-get-802-11-ds-status
# - https://stackoverflow.com/questions/843277/how-do-i-check-if-a-variable-exists
#
# Author: Victor Truan, Jerome Bagnoud | SWI - Labo 02 - Exo 02b

import argparse
from scapy.all import *

BROADCAST_MAC_ADDRESS = "ff:ff:ff:ff:ff:ff"
PAIR_LIST = list(tuple())

# Arguments
parser = argparse.ArgumentParser(description="Ce script permet d'afficher les d'afficher les STAs presentent dans la zone ainsi que l'AP auxquelles elles sont associe")
parser.add_argument("-i", "--interface", required=True, help="l'interface a utiliser")

arguments = parser.parse_args()

def handlePacket(packet):
    # Si c'est un packet de Data (type 2)    
    if(packet.type == 2):
        DS = packet.FCfield.value
        fromDS = bool(DS & 0x2)
        toDS = bool(DS & 0x1)

        # Les bits fromDS et toDS ont etes geres en accord avec la slide 57 du chapitre 1 du cours.
        # Wifi vers Ethernet
        # On filtre les adresses de Broadcast, mais on ne filtre pas les adresses multicast car nous n'avons pas trouve de moyen de le faire facilement
        if(toDS and not fromDS):
            stationMAC = packet.addr2
            apMAC = packet.addr1
        # Ethernet vers Wifi
        elif(fromDS and not toDS):
            stationMAC = packet.addr1
            apMAC = packet.addr2
        else:
            if(packet.addr1 != packet.addr3):
                stationMAC = packet.addr1
            if(packet.addr2 != packet.addr3):
                stationMAC2 = packet.addr2
            apMAC = packet.addr3

        if(stationMAC != BROADCAST_MAC_ADDRESS):
            apStaPair = (stationMAC, apMAC)

            # Avant d'ajouter la ligne on verfie si elle existe deja
            if(apStaPair not in PAIR_LIST):
                print(apStaPair[0] + " \t\t " + apStaPair[1])
                PAIR_LIST.append(apStaPair)
        
        try:
            if(stationMAC2 != BROADCAST_MAC_ADDRESS):
                apStaPair2 = (stationMAC2, apMAC)

                if(apStaPair2 not in PAIR_LIST):
                    PAIR_LIST.append(apStaPair2)
                    print(apStaPair2[0] + " \t\t " + apStaPair2[1])
                    stationMAC2 = None
        except:
            pass

print("STAs\t\t\t\t APs\n")

# On commence a sniffer, chaque packet collecte est envoye a la fonction handlePacket
a = sniff(iface=arguments.interface, prn=handlePacket)