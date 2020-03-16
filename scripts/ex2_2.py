from scapy.all import *
import os
import argparse
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11ProbeResp, Dot11ProbeReq, Dot11Ack

entries = dict()
BANNED_MAC_ADDRESS = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]

def scan(packet):
    '''
    Méthode permettant l'anaylse de paquet DATA afin de repertorier les AP ainsi que les STA communiquant avec ces dernières
    :param packet: Paquet à analyser
    '''
    addr1 = packet.addr1 #dest
    addr2 = packet.addr2 #source
    addr3 = packet.addr3 #bssid

    # On vérifie que le packet est bien de type DATA
    if packet.type == 2:
        if addr1 is not None and addr2 is not None and addr3 is not None and addr1 not in BANNED_MAC_ADDRESS:
            # On vérifie si le bssid est déjà présent, si non, on ajoute une netrée dans notre dictionnaire
            if addr3 not in entries:
                entries[addr3] = set()

            # Si l'adresse emettrice n'est pas égale au BSSID, on ajoute l'adresse dans l'entrée du dictionnaire correspondant au BSSID. Sinon on ajoute l'addr1.
            if addr2 != addr3 :
                entries[addr3].add(addr2)
            else:
                entries[addr3].add(addr1)


def printResult():
    '''
    Méthode permettant d'afficher les résultats
    '''
    print("Results : ")
    print("AP\t\t\t\tSTA")
    # On parcourt les bssids
    for bssid in entries:
        # On parcourt les STA correspondant au BSSID et on affiche
        for sta in entries[bssid]:
            print(bssid+"\t\t"+sta)



if __name__ == "__main__":
    # On recupere les arguments
    parser = argparse.ArgumentParser(description='Script listant toutes les STAs et APs ainsi que leur relation')
    parser.add_argument("--interface", required=True, help="Interface utilisée pour écouter")
    parser.add_argument("--timeout", required=False, help="Timeout du sniff. Default is 15")
    args = parser.parse_args()
    timeout = 15
    # Si l'argument timeout est spécifié par l'utilisateur on l'utilise, si non, par défaut c'est 15 secondes de sniff
    if(args.timeout is not None):
        timeout = args.timeout
    # On démarre le sniffing
    print("Sniffing....")
    sniff(iface=args.interface,timeout=int(timeout), prn=scan)
    printResult()