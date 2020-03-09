from scapy.all import *
import time
import threading
import os


HiddenBSSIDs = dict()

# Let user select network interface to perform attack
while(True): 
    ifaces = get_if_list() # Get interfaces in loop in case a new one appears
    iface = input(f"Name of desired interface to perform deauthentication attack {ifaces}: ")

    if(iface in ifaces):
        break

# Scan network on all channel
def change_channel(stop):
	ch = 1
	while True:
		os.system(f"iwconfig {iface} channel {ch}")
		# switch channel from 1 to 14 each 0.5s
		ch = ch % 14 + 1
		time.sleep(0.1)


		if stop():
			break


# Inspired by https://www.shellvoide.com/python/how-to-code-a-simple-wireless-sniffer-in-python/
# Called when sniff receive a packet
def callback(packet):
	if packet.haslayer(Dot11Beacon):
		# extract the MAC address of the network
		SSID = packet[Dot11Elt].info
		BSSID = packet.addr3

		stats = packet[Dot11Beacon].network_stats()
		# get the channel of the AP
		channel = stats.get("channel")

		print(".", end="", flush=True)


		if SSID == "" or packet[Dot11Elt].ID != 0:
			print("Yolo")
			HiddenBSSIDs[BSSID] = (channel)


def client_callback(packet):
	# Client connect to with beacon handler !!!!!
	



stop_threads = False

# start the channel changer
channel_changer = Thread(target=change_channel, args=(lambda: stop_threads,))
channel_changer.daemon = True
channel_changer.start()


# Sniff wifi packets for x seconds
SNIFF_DURATION = 600
print(f"Sniffing for {SNIFF_DURATION} seconds...")
sniff(prn=callback, iface=iface, timeout=SNIFF_DURATION)

# We don't need to switch channel anymore
stop_threads = True



# Display found SSIDs
if len(HiddenBSSIDs) > 0:
    print(f"\n{len(HiddenBSSIDs)} hidden BSSIDs found")

	print(f"BSSID - channel")

    for BSSID in HiddenBSSIDs:
        print(f"\t{BSSID} - {HiddenBSSIDs[BSSID]}")
else:
    print("\n No hidden BSSIDs found")
    exit()



ch = 1

# Let user select the network current channel
while(True): # Emulating do while in python
	ch = int(input("Select channel of the network to attack [1 - 14] : "))

	if(ch <= 14 and ch >= 1):
		os.system(f"iwconfig {iface} channel {ch}")
		break



print(f"Sniff on channel {ch} for STA connecting to hidden AP")
sniff(prn=client_callback, iface=iface)


input("Press any key to exit")



