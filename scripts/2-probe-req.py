import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11, Dot11Elt

# Add the arguments to the parser
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", required=True, help='Interface to use for sniffing')
args = parser.parse_args()


def packet_handler(p):
    dot11 = p.getlayer(Dot11)
    ssid = p[Dot11Elt][0].info
    print('{}    {}    {}'.format(dot11.addr2, dot11.addr1, ssid))


print('Started sniffing on interface', args.interface)
print('STA                  AP                   SSID')

sniff(iface=args.interface,
      prn=packet_handler,
      lfilter=lambda p: p.haslayer(Dot11ProbeReq),
      monitor=True)
