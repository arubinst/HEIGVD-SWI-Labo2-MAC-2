#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  Authors : Yimnaing Kamdem && Siu Aurelien
#  Objectif: Développer un script en Python/Scapy capable de générer une liste d'AP
#            visibles dans la salle et de STA détectés et déterminer quelle STA 
#            est associée à quel AP. Par exemple :
#
#            STAs                                       APs
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

interface = "wlan0mon"

def packetHandler(pkt):
    #TODO


# On sniffe en passant en fonction de callback la fonction packetHandler
sniff(count=300, iface=interface, prn=packetHandler)


 