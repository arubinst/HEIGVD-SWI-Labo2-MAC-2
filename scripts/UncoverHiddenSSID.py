#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  Authors  : yimnaing Kamdem && Siu Aurelien
#  Objectif : Développer un script en Python/Scapy capable de reveler le SSID 
#             correspondant à un réseau configuré comme étant "invisible".
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#import socket
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp

interface = "wlan0mon"

hidden_ssids_aps = set()
uncovered_ssids_aps = set()

# Source:   Scapy: Uncovering Hidden SSIDs
#           https://www.youtube.com/watch?v=_OpmfE43AiQ

def packetHandler(pkt):
    # Traitement si c'est un beacon frame
    if pkt.haslayer(Dot11Beacon):
        # Dresser une liste des SSID disponibles à proximité       
        if not pkt.info :
            if pkt.addr3 not in hidden_ssids_aps :
                hidden_ssids_aps.add(pkt.addr3)
                print("HIDDEN SSID Network Found! BSSID: ", pkt.addr3)
    # Traitement s'il s'agit d'une probe request
    elif Dot11ProbeResp in pkt and ( pkt.addr3 in hidden_ssids_aps ) :
        if pkt.addr3 not in uncovered_ssids_aps :
            uncovered_ssids_aps.add(pkt.addr3)
            print("Uncovered HIDDEN SSID Network Found! ", pkt.info.decode(), pkt.addr3)


print('Liste des AP invisibles')
# On sniffe en passant en fonction de callback la fonction packetHandler
sniff(iface=interface, prn=packetHandler)
  
