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


# initialize the networks dataframe that will contain all hidden access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel"])

# set the index BSSID (MAC address of the AP) for dataFrame
networks.set_index("BSSID", inplace=True)

def callback(packet):
	if packet.haslayer(Dot11Beacon):
		# extract the MAC address of the network
		bssid = packet[Dot11].addr2
		# get the name of it and its strength
		ssid = packet[Dot11Elt].info.decode()

		try:
			dbm_signal = packet.dBm_AntSignal
		except:
			dbm_signal = "N/A"
		# extract network stats
		stats = packet[Dot11Beacon].network_stats()
		# get the channel of the AP
		channel = stats.get("channel")
		# insert only hidden SSID in table
		if all(elem == '\x00' for elem in ssid):
			networks.loc[bssid] = ("hidden", dbm_signal, channel)

		# we wait for someone to connect to the AP and we get the info back
	elif packet.haslayer(Dot11ProbeResp) :

		bssid = packet.addr3
		if(bssid in networks.index):
			ssid = packet.info
			networks.loc[bssid][0] = ssid
			print(networks)


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