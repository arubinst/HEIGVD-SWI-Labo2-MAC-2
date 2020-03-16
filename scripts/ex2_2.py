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
    addr1 = packet.addr1
    addr2 = packet.addr2
    addr3 = packet.addr3

    # On vérifie que le packet est bien de type DATA
    if packet.type == 2:
        if addr1 is not None and addr2 is not None and addr3 is not None and addr1 not in BANNED_MAC_ADDRESS:
            # On vérifie si le bssid est déjà présent, si non, on ajoute une netrée dans notre dictionnaire

            # On recupere les ToDS et FromDS
            # Source : https://stackoverflow.com/questions/30811426/scapy-python-get-802-11-ds-status
            DS = packet.FCfield & 0x3
            to_DS = DS & 0x1 != 0
            from_DS = DS & 0x2 != 0



            #Ces operations sont basées sur les règles vues dans le cours (chapitre 1, slide 57)

            # Si la trame n'est pas to_DS et from_DS on ajoute addr1 et addr2
            if(not to_DS and not from_DS):
                if addr3 not in entries:
                    entries[addr3] = set()
                # Si l'adresse 3 est différente de l'adresse 1, on rajoute cette dernière
                if addr1 != addr3 :
                    entries[addr3].add(addr1)

                # Si l'adresse 3 est différente de l'adresse 2, on rajoute cette dernière
                if addr2 != addr3 :
                    entries[addr3].add(addr2)

            # Si la trame n'est pas to_DS mais est from_DS on ajoute addr1 (adresse de destination)
            elif(not to_DS and from_DS):
                if addr2 not in entries:
                    entries[addr2] = set()
                entries[addr2].add(addr1)

            # Si la trame est to_DS et pas from_DS, on ajoute addr2 (adresse source)
            elif(to_DS and not from_DS):
                if addr1 not in entries:
                    entries[addr1] = set()
                entries[addr1].add(addr2)
            else:
                return


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