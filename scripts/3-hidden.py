import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11ProbeResp, Dot11ProbeReq

# Add the arguments to the parser
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", required=True, help='Interface to use for sniffing')
args = parser.parse_args()
hidden_ssids = dict()


def packet_handler(p):
    """
    Source : https://ethicalhackingblog.com/uncovering-hidden-ssids/
    Principe :
    1. repérer les beacon frame sans ssid
    2. repérer les probe responses
    3. faire correspondre les addresses mac
    Eventuellement : pour avoir plus de probe responses on peut lancer une deauth attack.
    """
    if p.haslayer(Dot11Beacon):
        bssid = p.getlayer(Dot11).addr2.upper()
        try:
            p.info.decode('utf-8')
        except UnicodeDecodeError:
            # le wifi caché que nous avons créé n'avait pas simplement un ssid vide mais
            # une série de bytes à 0 puis d'autres bytes sans sens apparent, donc nous
            # avons utilisé cette "technique" pour savoir si nous avions à faire à un
            # wifi caché ou pas…
            if bssid not in hidden_ssids:
                print('Found hidden Wi-Fi with address', bssid)
                hidden_ssids[bssid] = None

    if p.haslayer(Dot11ProbeResp):
        bssid = p.getlayer(Dot11).addr2.upper()
        if bssid in hidden_ssids and hidden_ssids[bssid] is None:
            ssid = p.info.decode('utf-8')
            print('Found SSID "{}" for hidden Wi-Fi with BSSID {}'.format(ssid, bssid))
            hidden_ssids[bssid] = ssid


print('Started sniffing on interface', args.interface)
sniff(iface=args.interface,
      prn=packet_handler,
      monitor=True)
