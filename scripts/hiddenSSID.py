#!/usr/bin/python
'''
SWI - Labo2
Auteurs : Nemanja Pantic et David Simeonovic
But : Permet de découvrir le SSID d'un wifi cacher
Source : https://www.youtube.com/watch?v=_OpmfE43AiQ
'''

from scapy.all import *

hidden_ssid_aps = set()

#Permet de découvrir le nom d'un SSID caché
def PacketHandler(pkt):
    if pkt.haslayer(Dot11Beacon):
        if len(pkt[Dot11Elt].info.decode()) != 0:
            if pkt.addr3 not in hidden_ssid_aps:
                hidden_ssid_aps.add(pkt.addr3)
                print("Hidden SSID found : " + pkt.addr3)
    elif pkt.haslayer(Dot11ProbeResp) and (pkt.addr3 in hidden_ssid_aps):
        print("Hidden SSID uncovered : {0} --> {1}".format(pkt.info.decode(),pkt.addrp3))

#Demande le nom de l'interface à l'utilisateur
interface = input("Put your interface name : ")
sniff(iface=interface, prn=PacketHandler)

