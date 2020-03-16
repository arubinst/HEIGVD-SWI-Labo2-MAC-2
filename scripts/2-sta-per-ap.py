import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11AssoReq, Dot11AssoResp, Dot11ReassoReq, Dot11FCS

# Add the arguments to the parser
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", required=True, help='Interface to use for sniffing')
args = parser.parse_args()

# Contains all STAs associated to an AP.
# Keys are APs, values are a set of STAs.
state = {}

# clear console screen
clear = lambda: subprocess.call('clear')


def print_state():
    clear()
    print('STA                  AP')
    for ap in state:
        first = True
        for sta in state[ap]:
            if first:
                print('{}    {}'.format(ap, sta))
                first = False
            else:
                print('                     {}'.format(sta))


def packet_handler(p):
    # https://en.wikipedia.org/wiki/802.11_Frame_Types#Types_and_SubTypes
    # type 2 -> Data frames
    # On considère que si deux STA s'échangent des données alors elles sont
    # associées. On pourrait aussi observer les association requests et responses
    # mais si deux STA sont déjà associées on ne les verra pas.
    if p.haslayer(Dot11FCS) and p[Dot11FCS].type == 2:

        dot11 = p.getlayer(Dot11FCS)

        # Pour savoir qui est l'AP on compare addr1 ou addr2 avec addr3.
        if dot11.addr3 == dot11.addr1:
            ap = dot11.addr1
            sta = dot11.addr2
        elif dot11.addr3 == dot11.addr2:
            ap = dot11.addr2
            sta = dot11.addr1
        else:
            return  # ignoré

        # On met à jour l'état et on l'affiche
        if ap not in state:
            state[ap] = set()
        state[ap].add(sta)

        print_state()


print('Started sniffing on interface', args.interface)
sniff(iface=args.interface,
      prn=packet_handler,
      monitor=True)
