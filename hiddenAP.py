# Laboratoire 2 - Affichage des réseaux cachés
# usage: python3 hiddenAP.py -i wlan0mon
#
# Caroline monthoux - Rémi Poulard

from scapy.all import *
import argparse

parser = argparse.ArgumentParser(prog="Scapy hidden SSID reveal",
                                 usage="python3 hiddenAP.py -i wlan0mon",
                                 description="Scapy based wifi reveal")
parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")

args = parser.parse_args()

iface = args.Interface
bssid_found = {}

# Cette méthode va découvrir les réseaux cachés en regardant les trames de type beacon
# avec un SSID vide. Lorsqu'un client se connecte sur un réseau caché, la méthode
# va pouvoir ajouter le nom du réseau lié à cette adresse MAC
def discover_hidden_ssid(packet):
    if Dot11Elt in packet:
        # On connait déjà cette adresse, mais on n'avait pas le SSID correspondant
        if Dot11ProbeResp in packet and packet.addr3 in bssid_found:
            # On ajoute le SSID à l'adresse
            bssid_found[packet.addr3] = packet.info.decode("utf-8")

        # Le nom du SSID est vide et cette adresse n'est pas encore stockée
        elif Dot11Beacon in packet and packet.info.decode("utf-8") == '' and packet.addr3 not in bssid_found:
            # On a pas encore le SSID
            bssid_found[packet.addr3] = "Unknown"


print("Searching hidden SSID, please wait 15 seconds...")
sniff(iface=iface, prn=discover_hidden_ssid, timeout=15)

# Affichage des SSID trouvés
for ssid in bssid_found:
    print("{} {}".format(ssid, bssid_found[ssid]))
