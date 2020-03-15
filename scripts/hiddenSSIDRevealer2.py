#python3

import argparse
from scapy.all import *
from threading import Thread
import pandas
import time
import os
from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump

parser = argparse.ArgumentParser(prog="Hidden SSID Revealer",
								 usage=" python3 hiddenSSIDRevealer.py -i [interface] -s [secondes]\n",
								 allow_abbrev=False)
parser.add_argument("-i", "--Interface", required=True, help="Interface from which you want to monitor packets, needs to be set to monitor mode")
parser.add_argument("-s", "--Second", required=True, help="Number of second you will monitor packets")
args = parser.parse_args()


# initialize the networks dataframe that will contain all access points nearby
hidden_SSID = set()
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal"])


# set the index BSSID (MAC address of the AP) for dataFrame
networks.set_index("BSSID", inplace=True)

def callback(packet):
    try:
        dbm_signal = packet.dBm_AntSignal
    except:
        dbm_signal = "N/A"

    if packet.haslayer(Dot11Beacon) :
        ssid = packet[Dot11Elt].info.decode()
        if all(elem == '\x00' for elem in ssid) :
            hidden_SSID.add(packet.addr3)

    elif (packet.haslayer(Dot11ProbeResp) and (packet.addr3 in hidden_SSID)) :
        networks.loc[packet.addr3] = (packet.info.decode('utf-8'), dbm_signal)

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
