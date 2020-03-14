# Sources:
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
    if(packet.haslayer(Dot11Elt)):
        if packet.haslayer(Dot11ProbeResp) and packet[Dot11].addr3 in bssids:
            bssids[packet[Dot11].addr3] = packet.info.decode()
            printResults()
        elif packet.haslayer(Dot11Beacon):
            if(packet.info.decode().replace("\x00","") == "") and (packet[Dot11].addr3 not in bssids):
                bssids[packet[Dot11].addr3] = "UNKNOWN SSID"
                printResults()

def printResults():
    screen.clear()
    screen.addstr(0,0, "Sniffing.... (CTRL + C to stop)")
    screen.addstr(2,0, "BSSID\t\t\tSSID")
    index = 3
    for ssid in bssids:
        screen.addstr(index, 0, ssid + "\t" + bssids[ssid])
        index = index + 1
    screen.refresh()


def main(main_screen):
    global screen
    screen = curses.initscr()


    parser = argparse.ArgumentParser(description='Script listant toutes les hiddens SSIDs')
    parser.add_argument("--interface", required=True, help="Interface utilisée pour écouter")
    args = parser.parse_args()


    sniff(iface=args.interface, prn=scanHiddenSSIDs)

wrapper(main)
