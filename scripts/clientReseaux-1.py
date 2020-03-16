#!/usr/bin/env python
'''
SWI - Labo2
Auteurs : Nemanja Pantic et David Simeonovic
But : Permet de lister toutes les STA qui cherchent activement un SSID donné
'''

from scapy.all import *

STAs = set()

#Filtre les paquets pour n'avoir que les probe request et affiche le résultat 
def pkt_callback(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        if pkt.info.decode() == ssid_find and pkt.addr2 not in STAs:
            STAs.add(pkt.addr2)
            print("STA (%s) looking for the given SSID" % (pkt.addr2))


#Demande le ssid et l'interface à l'utilisateur
ssid_find = input("Select the SSID that you want to chase :")
interface = input("Put your interface name : ")

#Sniff les réseaux wifi
sniff(iface=interface, prn=pkt_callback, monitor=True)