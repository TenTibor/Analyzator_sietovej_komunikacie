from scapy.all import *

from frame import Frame

# load files and create db
# file = "eth-2.pcap"  # ethernet
# file = "trace-15.pcap"  # ARP
file = "trace-26.pcap"  # ARP

data = rdpcap('vzorky/' + file)
print(f"[File '{file}' was loaded]\n")
file = open('db.txt', "r")
protocols = []
for iProtocol in file:
    protocols.append(iProtocol.split(" "))

all_frames = []
# 1 - packet
# 2 - source port
communications_tftp = []
communications_arp = []
communications_icmp = []
allEthernetNodes = []


def tftp_communications():
    print("All TFTP communication minified")
    print("Count of all: " + str(len(communications_tftp)))
    for index, communication in enumerate(communications_tftp):
        print(f"Communication {str(index + 1)} - {len(communication[0])} frames")
        print(f"Source IP: {communication[0][0].sourceIpAddress}:{communication[0][0].sourcePort}    "
              f"Destination IP: {communication[0][0].destinationIpAddress}:{communication[0][0].destinationPort}")
        print("Packets:", communication[0], "\n")


def arp_communications():
    print("All ARP communication minified")
    print("Count of all: " + str(len(communications_arp)))
    print("========================")
    for index, pair in enumerate(communications_arp):
        print(f"Pair {str(index + 1)} - "
              f"{'Paired' if len(pair[2]) != 0 and len(pair[3]) != 0 else 'Not paired'}")
        print(f"Sender IP: {pair[0]} ",
              f"Target IP: {pair[1]}")
        print(f"Source MAC: {pair[4]} ",
              f"Destination MAC: {pair[5]}")
        print("Packets:", pair[2], pair[3], "\n")


def calc_all_frames():
    currDestinationPort = None
    currIndex = None

    for index, packet in enumerate(data):
        # get frame
        this_frame = Frame(packet, index + 1, protocols)
        all_frames.append(this_frame)

        # CALC MOST USED
        # get source ip from frame
        sourceIpAddress = this_frame.sourceIpAddress

        # Add source address to array if not exist. If yes.. Increase number of usage
        if this_frame.protocol == "IPv4":
            found = False
            for node in allEthernetNodes:
                if node[0] == sourceIpAddress:
                    node[1] += 1
                    found = True
            if not found:
                allEthernetNodes.append([sourceIpAddress, 1])

        # CALC TFTP
        # check if it is TFTP read request
        if this_frame.protocol_by_port == "TFTP":
            communications_tftp.append([
                [this_frame],
                this_frame.sourcePort
            ])
            if currIndex is None:
                currIndex = 0
            else:
                currIndex += 1
                currDestinationPort = None

        # check if this frame is part of TFTP communication
        if currIndex is not None and (this_frame.destinationPort == communications_tftp[currIndex][1]
                                      or this_frame.destinationPort == currDestinationPort):
            this_frame.protocol_by_port = "TFTP"
            if currDestinationPort is None:
                currDestinationPort = this_frame.sourcePort

            communications_tftp[currIndex][0].append(this_frame)

        # CALC ARP
        if this_frame.protocol == "ARP":
            found = False
            if this_frame.op_code == 1:
                for index, comm in enumerate(communications_arp):
                    if this_frame.sender_ip_address == comm[0] and this_frame.target_ip_address == comm[1]:
                        communications_arp[index][2].append(this_frame)
                        communications_arp[index][4] = this_frame.sourceMacAddress
                        found = True
                if not found:
                    communications_arp.append([
                        this_frame.sender_ip_address, this_frame.target_ip_address,
                        [this_frame], [],
                        this_frame.sourceMacAddress, "???"
                    ])

            elif this_frame.op_code == 2:
                for index, comm in enumerate(communications_arp):
                    if this_frame.sender_ip_address == comm[1] and this_frame.target_ip_address == comm[0]:
                        communications_arp[index][3].append(this_frame)
                        communications_arp[index][5] = this_frame.destinationMacAddress
                        found = True
                if not found:
                    communications_arp.append([
                        this_frame.target_ip_address, this_frame.sender_ip_address,
                        [], [this_frame],
                        "???", this_frame.sourceMacAddress,
                    ])

        # CALC ARP
        if this_frame.ipvProtocol == "ICMP":
            communications_icmp.append(this_frame)


def print_everything():
    for frame in all_frames:
        frame.print_frame()


def print_icmp():
    print("=== List of all ICMP protocols ===")
    for frame in communications_icmp:
        frame.print_frame()


def most_used_ip_addresses():
    # Print all ethernet source address
    print("=== List of all used IP address ===")
    for node in allEthernetNodes:
        print(node[0])

    # find most used and print it
    mostUsed = [None, 0]
    for node in allEthernetNodes:
        if node[1] > mostUsed[1]:
            mostUsed = node

    print(f"Most used address {mostUsed[0]} with {mostUsed[1]} pakets")
    print("=============================================")


calc_all_frames()

# INTERFACE
print_icmp()
# print_everything()
# arp_communications()
# tftp_communications()
# most_used_ip_addresses()

# userResponse = ""
# while userResponse != "q":
#     print("Actions list:")
#     print("2 - Most used IP address")
#     print("3 - All TFTP communications")
#     print("4 - All ARP communications")
#     print("5 - All ICMP communications")
#     print("q - Quit application")
#     print("----------------------------")
#     print("Type action > ", end="")
#     userResponse = input()
#     # userResponse = "1"
#     elif userResponse == "2":
#         most_used_ip_addresses()
#     elif userResponse == "3":
#         tftp_communications()
#     elif userResponse == "4":
#         arp_communications()
#     elif userResponse == "5":
#         print_icmp()
