from scapy.all import *

scapy_cap = rdpcap('vzorky/eth-1.pcap')
for index, packet in enumerate(scapy_cap):
    print(index, packet)
