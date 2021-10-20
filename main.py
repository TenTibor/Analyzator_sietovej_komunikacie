from scapy.all import *

from frame import Frame

# load files and create db
# file = "eth-1.pcap"  # http, https
# file = "trace-16.pcap"  # http tracking
# file = "trace-18.pcap"  # ssh tracking
# file = "trace-20.pcap"  # ssh tracking, http
# file = "eth-2.pcap"  # ethernet
file = "trace-15.pcap"  # ARP, ICMP
# file = "trace-26.pcap"  # ARP

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
        if this_frame.packetType == "IPv4":
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
        if this_frame.packetType == "ARP":
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
        if this_frame.transportProtocol == "ICMP":
            communications_icmp.append(this_frame)


def print_frames(frames):
    for frame in frames:
        frame.print_frame()


def print_frames_limits(frames):
    if len(frames) > 20:
        print("[First 10 frames]")
        print_frames(frames[:10])
        print("[Last 10 frames]")
        print_frames(frames[-11:-1])
    else:
        print_frames(frames)


def print_by_protocol(protocol):
    for frame in all_frames:
        if frame.protocol_by_port and frame.protocol_by_port.lower() == protocol.lower():
            frame.print_frame()


def print_communication_by_protocol(protocol):
    found_communications = []
    for frame in all_frames:
        if frame.protocol_by_port and frame.protocol_by_port.lower() == protocol.lower():
            if frame.flag is not None:
                # print(currIndex, frame, frame.flag)
                # Start of communication
                if frame.flag == "SYN":
                    found_communications.append(
                        [[frame], frame.destinationIpAddress, frame.sourcePort, False, False, False, None]
                        # closed, FIN-S, FIND-D, take last one
                    )
                else:
                    # find where communication belong
                    for comm in found_communications:
                        if comm[6] == frame.index:
                            comm[0].append(frame)
                        elif (comm[2] == frame.sourcePort or comm[2] == frame.destinationPort) and comm[3] is False:
                            comm[0].append(frame)

                            # Communication is ending soon
                            if frame.flag == "FIN, ACK":
                                comm[4 if frame.sourceIpAddress == comm[1] else 5] = True
                                if comm[4] is True and comm[5] is True:
                                    comm[6] = frame.index + 1

                            # Communication is ending
                            if frame.flag == "RST, ACK" or frame.flag == "RST" or (comm[4] is True and comm[5] is True):
                                comm[3] = True
                            break

    # Find first opened
    for index, communication in enumerate(found_communications):
        if communication[3] is False:
            print(protocol.upper() + " communication: (" + str(len(communication[0])) + " frames) - "
                  + ("Closed" if communication[3] else "Opened"))
            print_frames_limits(communication[0])
            break

    # Find first closed
    for index, communication in enumerate(found_communications):
        if communication[3] is True:
            print(protocol.upper() + " communication: (" + str(len(communication[0])) + " frames) - "
                  + ("Closed" if communication[3] else "Opened"))
            print_frames_limits(communication[0])
            break


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
# print_communication_by_protocol("http")
print_icmp()
# print_frames()
# arp_communications()
# tftp_communications()
# print_html()
# most_used_ip_addresses()

userResponse = ""
while userResponse == "q":
    print("Actions list:")
    print("1 - Everything")
    print("2 - Most used IP address")
    print("3 - All TFTP communications")
    print("4 - All ARP communications")
    print("5 - All ICMP communications")
    print("6 - Filter by protocol")
    print("7 - Find communication by protocol")
    print("q - Quit application")
    print("----------------------------")
    print("Type action > ", end="")
    userResponse = input()

    # userResponse = "1"
    if userResponse == "1":
        print_frames(all_frames)
    elif userResponse == "2":
        most_used_ip_addresses()
    elif userResponse == "3":
        tftp_communications()
    elif userResponse == "4":
        arp_communications()
    elif userResponse == "5":
        print_icmp()
    elif userResponse == "6":
        print("Type protocol > ", end="")
        protocol = input()
        print_by_protocol(protocol)
    elif userResponse == "7":
        print("Type protocol > ", end="")
        protocol = input()
        print_communication_by_protocol(protocol)
