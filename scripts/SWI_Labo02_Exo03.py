# Source:
#
# Author: Victor Truan, Jerome Bagnoud | SWI - Labo 02 - Exo 03

import argparse
import curses
from scapy.all import *

#BROADCAST_MAC_ADDRESS = "ff:ff:ff:ff:ff:ff"
PAIR_DICT = dict()

# Arguments
parser = argparse.ArgumentParser(description="")
parser.add_argument("-i", "--interface", required=True, help="l'interface a utiliser")

arguments = parser.parse_args()

def updateBSSIDDisplay(stdscr):
    stdscr.clear()
    stdscr.addstr(0,0,"BSSID MAC\t\t\t\t SSID")

    i = 2

    for bssid in PAIR_DICT.items():
        stdscr.addstr(i,0,bssid[0] + " \t\t\t " + bssid[1])
        i += 1

    stdscr.refresh()

# We use a nested function in order to pass argument to the sniff() callback function, source: https://gist.github.com/thepacketgeek/6876699
def packetHandling(stdscr):
    # This function verifiy if the packet is a management frame (more specifically a BeaconFrame), and read all necessary information from the packet (SSID, channel, etc...)
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
    # Avoid echoing the character typed and avoid delay for displaying things with curses library
    curses.noecho()
    stdscr.nodelay(1)

    stdscr.addstr(0,0,"BSSID MAC\t\t\t\t SSID")
    stdscr.refresh()

    # Begin to sniff, passing every packet collected to the packetHandling function
    a = sniff(iface=arguments.interface, prn=packetHandling(stdscr))

# Avoid bug with curses library while exiting the programm abruptely
curses.wrapper(main)