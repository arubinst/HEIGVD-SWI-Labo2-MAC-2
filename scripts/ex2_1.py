from scapy.all import *
import os
import argparse
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11ProbeResp, Dot11ProbeReq

ssidTarget = ""
stas = []

def scanSTA(packet):
    if Dot11ProbeReq in packet and Dot11Elt in packet[Dot11ProbeReq]:
        #print(packet.show())
        originalPacket = packet
        packet = packet[Dot11ProbeReq]
        packet = packet[Dot11Elt]
        if (packet.ID == 0):
            ssidFound = packet.info.decode("utf-8")
            addr = originalPacket.addr2
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

    print("Sniffing....")
    print("Ci-dessous, la liste des STAs cherchant à se connecter au SSID " + ssidTarget + " : ")
    sniff(iface=args.interface, prn=scanSTA)