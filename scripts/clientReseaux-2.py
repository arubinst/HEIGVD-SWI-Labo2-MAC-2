#!/usr/bin/python
'''
SWI - Labo2
Auteurs : Nemanja Pantic et David Simeonovic
But : Permet de lister les STA associés à un AP
Source : https://www.shellvoide.com/python/finding-connected-stations-of-access-point-python-scapy/
'''

from scapy.all import *

def pkt_callback(pkt):
    ap = sta = ""
    
    if pkt.haslayer(Dot11FCS) and pkt[Dot11FCS].type == 2:
        #Permet de savoir lequel est l'ap et le sta
        if pkt.getlayer(Dot11FCS).addr3 == pkt.getlayer(Dot11FCS).addr1:
            ap = pkt.getlayer(Dot11FCS).addr1
            sta = pkt.getlayer(Dot11FCS).addr2
        elif pkt.getlayer(Dot11FCS).addr3 == pkt.getlayer(Dot11FCS).addr2:
            ap = pkt.getlayer(Dot11FCS).addr2
            sta = pkt.getlayer(Dot11FCS).addr1
        if ap != "" and sta != "" :
            print("AP (%s) > STA (%s)" % (ap, sta))

#Demande l'interface à l'utilisateur
interface = input("Put your interface name : ")

#Sniff les réseaux wifi
sniff(iface=interface, prn=pkt_callback, monitor=True)