# Laboratoire 2 - Affichage d'une liste de STA et de l'AP à laquelle elle est connectée
# usage: python3 list_sta_ap.py -i wlan0mon
#
# Caroline monthoux - Rémi Poulard

from scapy.all import *
from threading import Thread, Event
import argparse

# Gestion des arguments
parser = argparse.ArgumentParser(prog="Scapy list client earching for a SSID", usage="python3 list_sta_ap.py -i wlan0mon", description="Scapy list STA searching for a specific SSID")
parser.add_argument("-i", "--Interface", required=True, help="The interface that you want to send packets out of, needs to be set to monitor mode")

args = parser.parse_args()


# Classe qui implémente un thread et qui nous permet de sniffer en continu
class Sniffer(Thread):
    def  __init__(self, interface="wlan0mon"):
        super().__init__()

        self.interface = interface
        self.stop_sniffer = Event()
        # list des liens AP - STA
        self.links = []

    # lorsque l'on reçoit un 'join', on set l'événement qui permettra de stopper
    # le thread lorsqu'il vérifiera le statut de l'événement
    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    # Regarde si l'événement est set ou pas. S'il l'est, nous retournons true
    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    # On affiche la paire trouvée
    def print_ap_sta_link(self, addrAP, addrSTA):
        print("{addrAP}\t\t{addrSTA}".format(addrAP=addrAP, addrSTA=addrSTA))

    # On vérifie que le packet soit un data et qu'il soit envoyé en unicast
    def find_link_ap_sta(self, packet):
        # On vérifie que ce soit bien un packet de données, puis qu'il ne soit pas en broadcast
        if  packet.type == 2 and packet.addr1 != "ff:ff:ff:ff:ff:ff" and packet.addr2 != "ff:ff:ff:ff:ff:ff":
            # On ne veut pas afficher les adresses de multicast
            if packet.addr1.startswith("01:00:5e") or packet.addr2.startswith("01:00:5e") or packet.addr1.startswith("33:33") or packet.addr2.startswith("33:33"):
                return
            # Permet de différencier l'adresse de l'AP et de la STA
            if packet.addr1 == packet.addr3:
                addrAP = packet.addr1
                addrSTA = packet.addr2
            elif packet.addr2 == packet.addr3:
                addrAP = packet.addr2
                addrSTA = packet.addr1
            else:
                return

            link = (addrAP, addrSTA)
            if link not in self.links:
                self.links.append((addrAP, addrSTA))

                # On affiche le lien entre l'AP et la STA
                self.print_ap_sta_link(addrAP, addrSTA)

    # Action lorsque le thread démarre
    def run(self):
        sniff(iface=self.interface, prn=self.find_link_ap_sta, stop_filter=self.should_stop_sniffer)


sniffer = Sniffer()

print("[*] Start sniffing...")
print("AP \t\t\t\t STA")
sniffer.start()

try:
    while True:
        pass
except KeyboardInterrupt:
    print("[*] Stop sniffing")
    # On demande à arreter le thread
    sniffer.join()
