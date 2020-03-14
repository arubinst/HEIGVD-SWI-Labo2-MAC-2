# Sources:
# - https://docs.python.org/3/howto/curses.html
# - https://www.devdungeon.com/content/curses-programming-python#toc-20


import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11, RadioTap
import curses
from curses import *

bssids = dict()

screen = None
interface = None

def scanHiddenSSIDs(packet):
    if(packet.haslayer(Dot11Elt)):
        if packet.haslayer(Dot11ProbeResp) and packet[Dot11].addr3 in bssids:
            bssids[packet[Dot11].addr3] = packet.info.decode()
            printResults()
        elif packet.haslayer(Dot11Beacon):
            if(packet.info.decode() == b'\x00\x00\x00\x00\x00\x00\x00\x00'.decode('utf8')) and (packet[Dot11].addr3 not in bssids):
                bssids[packet[Dot11].addr3] = "UNKNOWN SSID"
                printResults()
                sendBeacon(packet[Dot11].addr3)

def printResults():
    screen.clear()
    screen.addstr(0,0, "Sniffing.... (CTRL + C to stop)")
    screen.addstr(2,0, "BSSID\t\t\tSSID")
    for ssid in bssids:
        screen.addstr(3, 0, ssid + "\t" + bssids[ssid])
    screen.refresh()

def sendBeacon(bssid):
    packet = RadioTap()/Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(),addr3="ff:ff:ff:ff:ff:ff")/Dot11Elt(ID="SSID", info="")
    sendp(packet, interface)

def main(main_screen):
    global screen
    global interface
    screen = curses.initscr()

    parser = argparse.ArgumentParser(description='Script listant toutes les hiddens SSIDs')
    parser.add_argument("--interface", required=True, help="Interface utilisée pour écouter")
    args = parser.parse_args()
    interface = args.interface

    sniff(iface=args.interface, prn=scanHiddenSSIDs)

wrapper(main)
