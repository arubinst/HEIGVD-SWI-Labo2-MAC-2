#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  Authors : Yimnaing Kamdem && Siu Aurelien
#  Objectif: Développer un script en Python/Scapy capable de lister 
#            toutes les STA qui cherchent activement un SSID donné
#
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

import sys
from scapy.all import *
import argparse
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11ProbeResp, Dot11ProbeReq

stations  = []

# Arguments
parser = argparse.ArgumentParser(description="script capable de lister toutes les STA qui cherchent activement un SSID donné")
parser.add_argument("-i", "--interface", required=True, help="interface d'écoute")
parser.add_argument("--ssid", required=True, type=str, help="le SSID a donné")

arguments = parser.parse_args()

def packetHandler(packet):
    if Dot11ProbeReq in packet and Dot11Elt in packet[Dot11ProbeReq]:
        copiedPacket = packet
        packet = packet[Dot11ProbeReq]
        packet = packet[Dot11Elt]
        if (packet.ID == 0):
            ssid = packet.info.decode("utf-8")
            adr  = copiedPacket.addr2
            if((ssid == arguments.ssid) and (adr not in stations)):
                stations.append(adr)
                print(adr)

print("STAs recherchant le ssid " + arguments.ssid + " : \n")

# On sniffe en passant en fonction de callback la fonction packetHandler
sniff(count=1000, iface=arguments.interface, prn=packetHandler)
