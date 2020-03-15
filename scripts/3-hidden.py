import argparse

from scapy.all import *

# Add the arguments to the parser
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", required=True, help='Interface to use for sniffing')
args = parser.parse_args()


def packet_handler(p):
    # https: // ethicalhackingblog.com / uncovering - hidden - ssids /
    # repérer les beacon frame sans ssid
    # repérer les probe responses
    # faire correspondre les addresses mac
    # pour avoir plus de probe responses on peut lancer une deauth attack
    return


print('Started sniffing on interface', args.interface)
sniff(iface=args.interface,
      prn=packet_handler,
      monitor=True)
