# Sources pour curses:
# - https://docs.python.org/3/howto/curses.html
# - https://www.devdungeon.com/content/curses-programming-python#toc-20


import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11
import curses
from curses import *

bssids = dict()

screen = None

def scanHiddenSSIDs(packet):
    '''
    Méthode permettant de traiter les paquets afin de chercher les SSIDs cachés. On va repertorier les BSSIDs des SSIDs cachés et lorsque un client va se connecter à un d'eux, il va emettre un probe request et recevoir un probe response.
    On va lire dans ce dernier afin de récuperer le nom.
    :param packet: Paquet à analyser
    '''
    #On vérifie si le paquet contient le layer Dot11Elt
    if(packet.haslayer(Dot11Elt)):
        # On vérifie si c'est une Probe Response et si l'adresse du probe response est contenu dans les BSSIDs que l'on recherche
        if packet.haslayer(Dot11ProbeResp) and packet[Dot11].addr3 in bssids:
            #On ajoute le nom du SSID au BSSID correspondant
            bssids[packet[Dot11].addr3] = packet.info.decode()
            #On affiche les resultats
            printResults()
        # On vérifie si c'est un Beacon
        elif packet.haslayer(Dot11Beacon):
            # Si le beacon ne contient pas de nom, et qu'il n'est pas deja repertorier on l'ajoute à notre liste
            if(packet.info.decode().replace("\x00","") == "") and (packet[Dot11].addr3 not in bssids):
                bssids[packet[Dot11].addr3] = "UNKNOWN SSID"
                # On affiche les résultats
                printResults()

def printResults():
    '''
    Méthode permettant d'afficher les résultats
    '''
    screen.clear()
    screen.addstr(0,0, "Sniffing.... (CTRL + C to stop)")
    screen.addstr(2,0, "BSSID\t\t\tSSID")
    index = 3
    # On affiche les bssids et leur ssid s'il existe, autrement on affiche "UNKKWON SSID"
    for ssid in bssids:
        screen.addstr(index, 0, ssid + "\t" + bssids[ssid])
        index = index + 1
    screen.refresh()


def main(main_screen):
    global screen
    screen = curses.initscr()

    #Parsing des arguments
    parser = argparse.ArgumentParser(description='Script listant toutes les hiddens SSIDs')
    parser.add_argument("--interface", required=True, help="Interface utilisée pour écouter")
    args = parser.parse_args()

    # On lance le sniffing
    sniff(iface=args.interface, prn=scanHiddenSSIDs)

wrapper(main)
