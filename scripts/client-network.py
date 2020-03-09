from scapy.all import *
import time
import threading
import os

APs = dict()


def is_broadcast(mac):
    return mac == "FF:FF:FF:FF:FF:FF"

# Inspired by https://www.shellvoide.com/python/finding-connected-stations-of-access-point-python-scapy/
# Called when sniff receive a packet
def pkt_callback(packet):
    # It is a beacon, if we don't know the AP it is added to a dictionary
    if packet.haslayer(Dot11Beacon):
        bssid = packet.getlayer(Dot11).addr2.upper()
        if bssid not in APs:
            ssid = packet[Dot11Elt].info.decode()
            APs[bss] = {
                "SSID": ssid,
                "STA": set() # A list of associated stations
            }

    # It's a data frame
    elif packet.haslayer(Dot11) and packet.getlayer(Dot11).type == 2 and not packet.haslayer(EAPOL):
        sn = packet.getlayer(Dot11).addr2.upper()
        rc = packet.getlayer(Dot11).addr1.upper()

        # We don't want Broadcasts
        if is_broadcast(sn) or is_broadcast(rc):
            return

        if sn in APs:
            APs[sn]["STA"].add(rc)
        elif rc in APs:
            APs[rc]["STA"].add(sn)

# Scan network on all channel
def change_channel(stop, iface):
	ch = 1
	while True:
		os.system(f"iwconfig {iface} channel {ch}")
		# switch channel from 1 to 14 each 0.5s
		ch = ch % 14 + 1
		time.sleep(0.1)

		if stop():
			break

# Print networks infos
def print_all(stop):
    while True:
        cpAPs = APs.copy()

        os.system("clear")

        for MAC in cpAPs:
            ssid = cpAPs[MAC]["SSID"]
            print(f"{ssid} - {MAC}")

            for STA in cpAPs[MAC]["STA"]:
                print(f"\t{STA}")

            print("")

        print("\nPlease wait a few second while sniffing near networks...")
        time.sleep(1)

        if stop():
            break

iface = "wlan0mon"

stop_threads = False

# start the channel changer
channel_changer = Thread(target=change_channel, args=(lambda: stop_threads,iface,))
channel_changer.daemon = True
channel_changer.start() 

# start the thread that prints all the networks
stop_threads = False
printer = Thread(target=print_all, args=(lambda: stop_threads,))
printer.daemon = True
printer.start()
            
sniff(iface=iface, prn=pkt_callback)