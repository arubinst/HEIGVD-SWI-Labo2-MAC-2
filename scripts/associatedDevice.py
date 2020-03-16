#python3

import argparse
from scapy.all import *
from threading import Thread
import pandas
import time
import os
from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump

parser = argparse.ArgumentParser(prog="Associated Devices",
                                 usage=" python3 associatedDevices.py -i [interface] -s [secondes]\n",
                                 allow_abbrev=False)
parser.add_argument("-i", "--Interface", required=True, help="Interface from which you want to monitor packets, needs to be set to monitor mode")
parser.add_argument("-s", "--Second", required=True, help="Number of second you will monitor packets")
args = parser.parse_args()


# Initialize the networks dataframe that will contain all access points associated with STA and initialize aps that will contains a set of APs
networks = pandas.DataFrame(columns=["AP", "STA"])
aps = set()

# set the index AP (MAC address of the AP) for dataFrame
networks.set_index("STA", inplace=True)

# Sources : https://www.shellvoide.com/python/finding-connected-stations-of-access-point-python-scapy/
def callback(packet):
    if packet.haslayer(Dot11Beacon):
        ap = packet.getlayer(Dot11).addr2
        aps.add(ap)

    # This means it's a 802.11 dataframe between an authenticated client and an AP
    if packet.haslayer(Dot11FCS) and packet.getlayer(Dot11FCS).type == 2:
        src = packet.getlayer(Dot11FCS).addr2
        dst = packet.getlayer(Dot11FCS).addr1
        # Identify who's AP and who's STA, also filtering broadcast
        if dst in aps and (src != 'ff:ff:ff:ff:ff:ff' and dst != 'ff:ff:ff:ff:ff:ff'):
            networks.loc[src] = (dst)
        elif src in aps and (src != 'ff:ff:ff:ff:ff:ff' and dst != 'ff:ff:ff:ff:ff:ff'):
            networks.loc[dst] = (src)
        

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)

if __name__ == "__main__":

    # interface name, secondes of scanning
    interface = args.Interface   
    second = args.Second 

    # the channel changer has been taken from : https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy
    # the callback function has been inspired by it as well
    # start the channel changer 
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing
    print("Sniffing for " + str(second) + " seconds, please wait\n")
    sniff(prn=callback, iface=interface, timeout=int(second))
    print(networks)