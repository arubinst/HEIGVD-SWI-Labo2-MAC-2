import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11, Dot11Elt

# Add the arguments to the parser
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", required=True, help='Interface to use for sniffing')
args = parser.parse_args()


def packet_handler(packet):
    dot11 = packet.getlayer(Dot11)
    ssid = packet[Dot11Elt].info
    print('{}    {}    {}'.format(dot11.addr2, dot11.addr1, ssid.decode('utf-8')))
    # if ssid == b'':
    #     print(packet.show())


print('Started sniffing on interface', args.interface)
print('STA                  AP                   SSID')

sniff(iface=args.interface,
      prn=packet_handler,
      lfilter=lambda p: p.haslayer(Dot11ProbeReq) and p[Dot11Elt].ID == 0,
      monitor=True)
