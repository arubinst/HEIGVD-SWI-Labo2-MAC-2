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

from scapy.all import *

interface = "wlan0mon"

clientProbes = set()
 
# fonction appelée pour chaque paquet sniffé
def packetHandler(pkt):

    if pkt.haslayer(Dot11ProbeReq):
        #print(pkt.addr2 + "---" + pkt.info.decode("utf-8"))
        if len(pkt.info) > 0 :
            probe = pkt.addr2 + "-" + pkt.info.decode("utf-8")
            #print(probe)
            if probe not in clientProbes :
                clientProbes.add(probe)
                print ("New Probe Found : " + pkt.addr2 + ' ' + pkt.info.decode("utf-8"))
                
 



# On sniffe en passant en fonction de callback la fonction sniffing
sniff(count=400, iface=interface, prn=packetHandler)
    
