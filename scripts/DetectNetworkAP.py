#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  Authors : Yimnaing Kamdem && Siu Aurelien
#  Objectif: Développer un script en Python/Scapy capable de générer une liste d'AP
#            visibles dans la salle et de STA détectés et déterminer quelle STA 
#            est associée à quel AP. Par exemple :
#
#            STAs                                    APs
#
#            B8:17:C2:EB:8F:8F             08:EC:F5:28:1A:EF
#
#            9C:F3:87:34:3C:CB             00:6B:F1:50:48:3A
#
#            00:0E:35:C8:B8:66             08:EC:F5:28:1A:EF
#
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

import sys
from scapy.all import *
import argparse

interface = "wlan0mon"
BROADCAST_ADR = "ff:ff:ff:ff:ff:ff"
sta = ""
ssid = ""

STAsAndAPs = set(tuple())


def packetHandler(packet):

    #cas des pacquets pas Dot11, et des paquets Dot 11 dont les adresses mac src ou dst sont des addresses de broadcast
    if not packet.haslayer(Dot11Elt) or ((packet.addr3 == BROADCAST_ADR) or (packet.addr1 == BROADCAST_ADR)):
        return
        
    #cas ou la station est emettrice 
    if (packet.addr2 != packet.addr3):
        sta = packet.addr2
	ssid = packet.addr1 
            
    #cas ou l'AP est emetteur
    elif (packet.addr1 != packet.addr3):
        ssid = packet.addr3
	sta = packet.addr1

    current_set = (sta, ssid)   
            
    if(current_set not in STAsAndAPs):
      
        STAsAndAPs.add(current_set)
        print(current_set[0] + " \t\t " + current_set[1])

print("STAs \t\t\t\t APs\n")

# On sniffe en passant en fonction de callback la fonction packetHandler
sniff(count=600, iface=interface, prn=packetHandler)