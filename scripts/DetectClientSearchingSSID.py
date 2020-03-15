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

interface = "wlan0mon"

def packetHandler(pkt):
    #TODO


# On sniffe en passant en fonction de callback la fonction packetHandler
sniff(count=300, iface=interface, prn=packetHandler)


 