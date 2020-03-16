# Laboratoire 2 - Listage des STA en cherchant un SSID donné
# usage: python3 list_ap.py -i wlan0mon -s freewifi
#
# Caroline monthoux - Rémi Poulard

from scapy.all import *
from threading import Thread, Event
from time import sleep
import argparse

# Gestion des arguments
parser = argparse.ArgumentParser(prog="Scapy list client earching for a SSID", usage="python3 list_ap.py -i wlan0mon -s freewifi", description="Scapy list STA searching for a specific SSID")
parser.add_argument("-i", "--Interface", required=True, help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-s", "--ssid", required=True, help="The interface that you want to send packets out of, needs to be set to monitor mode")

args = parser.parse_args()


# Classe qui implémente un thread et qui nous permet de sniffer en continu
class Sniffer(Thread):
    def  __init__(self, interface="wlan0mon"):
        super().__init__()

        self.interface = interface
        self.stop_sniffer = Event()

    # lorsque l'on reçoit un 'join', on set l'événement qui permettra de stopper
    # le thread lorsqu'il vérifiera le statut de l'événement
    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    # Regarde si l'événement est set ou pas. S'il l'est, nous retournons true
    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    # On affiche l'AP qui a été trouvé
    def print_ap_found(self, addr):
        print("Cliend addr {addr}".format(addr=addr))

    # On vérifie que le packet est un probe request, puis on vérifie que son SSID
    # soit le même que celui que l'on cherche
    def find_ssid_searched(self, packet):
        if packet.haslayer(Dot11ProbeReq) and packet.info.decode("utf-8") == args.ssid:

            # On affiche le client
            self.print_ap_found(packet.addr2)

    # Action lorsque le thread démarre
    def run(self):
        sniff(iface=self.interface, prn=self.find_ssid_searched, stop_filter=self.should_stop_sniffer)


sniffer = Sniffer()

print("[*] Start sniffing...")
sniffer.start()

# Ce thread attend que l'utilisateur fasse un contrôle+C pour ordonner à l'autre thread de s'arrêter.
try:
    while True:
        pass
except KeyboardInterrupt:
    print("[*] Stop sniffing")
    sniffer.join()
