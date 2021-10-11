from scapy.all import *

scapy_cap = rdpcap('vzorky/eth-1.pcap')
for packet in scapy_cap:
    print(packet)
