# Source:
# - https://gist.github.com/thepacketgeek/6876699
# - https://docs.python.org/3/howto/curses.html
#
# Author: Victor Truan, Jerome Bagnoud | SWI - Labo 02 - Exo 03

import argparse
import curses
from scapy.all import *

PAIR_DICT = dict()
BROADCAST_MAC_ADDRESS = "FF:FF:FF:FF:FF:FF"

# Arguments
parser = argparse.ArgumentParser(description="Ce script permet de detecter les SSID cache, et d'essayer de les reveler en lisant les Probe response de ces APs")
parser.add_argument("-i", "--interface", required=True, help="l'interface a utiliser")

arguments = parser.parse_args()

# Met l'affichage des BSSID avec leur nom respectif a jour
def updateBSSIDDisplay(stdscr):
    # On efface d'abord ce qui est affiche dans le terminal
    stdscr.clear()
    stdscr.addstr(0,0,"BSSID MAC\t\t\t\t SSID")

    i = 2

    for bssid in PAIR_DICT.items():
        stdscr.addstr(i,0,bssid[0] + " \t\t\t " + bssid[1])
        i += 1

    stdscr.refresh()

# On utilise une fonction neste afin de passer un argument supplémentaire au callback de sniff, source: https://gist.github.com/thepacketgeek/6876699
def packetHandling(stdscr):
    # Cette fonction verifie si le packet, est un Beacon ou une probe response, dans le cas d'un Beacon on va regarder si le SSID est cache, si c'est le cas on va le sauvegarder dans un dictionnaire
    # puis si c'est un packet de Probe response, on va regarder si l'addresse est presente dans le dictionnaire et mettre a jour le SSID dans ce cas.
    def decloakSSID(packet):
        # Probe response
        if(packet.type == 0 and packet.subtype == 5):
            macTMP = packet.addr2
            if PAIR_DICT.get(macTMP) != None:
                PAIR_DICT[macTMP] = packet.info.decode()

            updateBSSIDDisplay(stdscr)
        # Beacon frame
        elif(packet.type == 0 and packet.subtype == 8 and packet.info.decode() == ""):
            if(packet.addr2 not in PAIR_DICT):
                PAIR_DICT[packet.addr2] = packet.info.decode()
                updateBSSIDDisplay(stdscr)

    return decloakSSID

def main(stdscr):
    # Empeche l'ecriture des caractere tape par curses
    curses.noecho()
    stdscr.nodelay(1)

    stdscr.addstr(0,0,"BSSID MAC\t\t\t\t SSID")
    stdscr.refresh()

    # On commence a sniffer, chaque packet collecte est envoye a la fonction handlePacket
    a = sniff(iface=arguments.interface, prn=packetHandling(stdscr))

# Empeche les bug d'affichage avec la librairie curses, si le programme se quiite brutalement
curses.wrapper(main)