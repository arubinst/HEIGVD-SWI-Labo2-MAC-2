
from scapy.all import *
from threading import Thread, Event
from time import sleep
import argparse

parser = argparse.ArgumentParser(prog="Scapy list client earching for a SSID",
                                 usage="python3 list_ap.py -i wlan0mon -s freewifi",
                                 description="Scapy list STA searching for a specific SSID")
parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-s", "--ssid", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")

args = parser.parse_args()


# Class qui implemente un thread et qui nous permet de sniffer en continue
class Sniffer(Thread):
    def  __init__(self, interface="wlan0mon"):
        super().__init__()

        self.interface = interface
        self.stop_sniffer = Event()

    # lorsque on recoit un join on set l'evenement ce qui permettra de stopper
    # le thread lorsque il verifira le status de l'evenement
    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    # Est-ce que l'evenement est set ou pas
    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()
    
    # On affiche l'AP qui a été trouvé
    def print_ap_found(self, addr):
        print("Cliend addr {addr}".format(addr=addr))
    
    # On verifie que le packet est une prob request puis on regarde que son ssid
    # soit le même que celui que l'on cherche
    def find_ssid_searched(self, packet):
        if  packet.haslayer(Dot11ProbeReq) and packet.info.decode("utf-8") == args.ssid: 
            
            # On affiche le client
            self.print_ap_found(packet.addr2)
    
    # Action lorsque le thread demarre
    def run(self):
        sniff(iface=self.interface, prn=self.find_ssid_searched, stop_filter=self.should_stop_sniffer)


sniffer = Sniffer()

print("[*] Start sniffing...")
sniffer.start()

try:
    while True:
        sleep(100)
except KeyboardInterrupt:
    print("[*] Stop sniffing")
    sniffer.join()
