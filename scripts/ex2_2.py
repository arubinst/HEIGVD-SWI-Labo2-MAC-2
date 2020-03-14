from scapy.all import *
import os
import argparse
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11ProbeResp, Dot11ProbeReq, Dot11Ack

entries = dict()
BANNED_MAC_ADDRESS = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]

def scan(packet):
    addr1 = packet.addr1 #dest
    addr2 = packet.addr2 #source
    addr3 = packet.addr3 #bssid

    if packet.type == 2:
        if addr1 is not None and addr2 is not None and addr3 is not None and addr1 not in BANNED_MAC_ADDRESS:

            # On vérifie si le bssid est déjà présent
            if addr3 not in entries:
                entries[addr3] = set()

            if addr2 != addr3 :
                entries[addr3].add(addr2)
            else:
                entries[addr3].add(addr1)


def printResult():
    print("Results : ")
    print("AP\t\t\t\tSTA")
    for bssid in entries:
        for ap in entries[bssid]:
            print(bssid+"\t\t"+ap)



if __name__ == "__main__":
    # On recupere les arguments
    parser = argparse.ArgumentParser(description='Script listant toutes les STAs et APs ainsi que leur relation')
    parser.add_argument("--interface", required=True, help="Interface utilisée pour écouter")
    parser.add_argument("--timeout", required=False, help="Timeout du sniff. Default is 15")
    args = parser.parse_args()
    timeout = 15
    if(args.timeout is not None):
        timeout = args.timeout
    print("Sniffing....")
    sniff(iface=args.interface,timeout=int(timeout), prn=scan)
    printResult()