from scapy.all import *
import argparse
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11ProbeResp, Dot11ProbeReq

ssidTarget = ""
stas = []

def scanSTA(packet):
    '''
    Methode permettant de scanner les paquets à la recherche d'un SSID spécifique
    :param packet: Paquet à analyser
    '''

    # On verifie si c'est une Probe request
    if Dot11ProbeReq in packet and Dot11Elt in packet[Dot11ProbeReq]:
        originalPacket = packet
        packet = packet[Dot11ProbeReq]
        packet = packet[Dot11Elt]
        # On regarde si le champs est celui qui contient le nom
        if (packet.ID == 0):
            # On recupere le SSID du paquet
            ssidFound = packet.info.decode("utf-8")
            # On recupere l'adresse Mac de l'emetteur de la probe request
            addr = originalPacket.addr2
            # Si l'adresse MAC n'est pas déjà repertoriée et si le ssid trouvé et celui cherché, on ajoute l'adresse MAC à notre liste et on l'affiche
            if((addr not in stas) and (ssidFound == ssidTarget)):
                stas.append(addr)
                print(addr)



if __name__ == "__main__":
    # On recupere les arguments
    parser = argparse.ArgumentParser(description='Script listant toutes les STAs cherchant un SSID donné')
    parser.add_argument("--interface", required=True, help="Interface utilisée pour écouter")
    parser.add_argument("--ssid", required=True, help="SSID cible")
    args = parser.parse_args()
    ssidTarget = args.ssid

    #On lance le sniffing sans limite de temps
    print("Sniffing....")
    print("Ci-dessous, la liste des STAs cherchant à se connecter au SSID " + ssidTarget + " : ")
    sniff(iface=args.interface, prn=scanSTA)