from scapy.all import *

from frame import Frame

# load files and create db
# file = "eth-2.pcap"  # ethernet
file = "trace-15.pcap"  # ARP
data = rdpcap('vzorky/' + file)
print(f"[File '{file}' was loaded]\n")
file = open('db.txt', "r")
protocols = []
for iProtocol in file:
    protocols.append(iProtocol.split(" "))


def tftp_communications():
    communications = []
    # 1 - packet
    # 2 - source port
    currDestinationPort = None
    currIndex = None
    for index, packet in enumerate(data):
        # get frame
        this_frame = Frame(packet, index + 1, protocols)

        # check if it is TFTP read request
        if this_frame.protocol_by_port == "TFTP":
            communications.append([
                [this_frame.index],
                this_frame.sourcePort
            ])
            if currIndex is None:
                currIndex = 0
            else:
                currIndex += 1
                currDestinationPort = None

        # check if this frame is part of TFTP communication
        print(index + 1, this_frame.destinationPort, currDestinationPort)
        if currIndex is not None and (this_frame.destinationPort == communications[currIndex][1]
                                      or this_frame.destinationPort == currDestinationPort):
            this_frame.protocol_by_port = "TFTP"
            if currDestinationPort is None:
                currDestinationPort = this_frame.sourcePort
            communications[currIndex][0].append(
                this_frame.index,
            )
            # if len(communications[currIndex])

        # print frame
        # this_frame.print_frame()
    print("All TFTP communication minified")
    print("Count of all: " + str(len(communications)))
    for index, communication in enumerate(communications):
        print(f"Communication {str(index + 1)} ({len(communication[0])}), src: {communication[1]}")
        print("Packets:", communication[0])
        # print("Packets: " + communication[index][0])


def all_frames():
    for index, packet in enumerate(data):
        # get frame
        this_frame = Frame(packet, index + 1, protocols)
        # print frame
        this_frame.print_frame()


def most_used_ip_addresses():
    allEthernetNodes = []
    for index, packet in enumerate(data):

        # get frame
        this_frame = Frame(packet, index + 1, protocols)

        # get source ip from frame
        sourceIpAddress = this_frame.sourceIpAddress

        # Add source address to array if not exist. If yes.. Increase number of usage
        if this_frame.protocol == "IPv4":

            # print frame
            this_frame.print_frame()

            found = False
            for node in allEthernetNodes:
                if node[0] == sourceIpAddress:
                    node[1] += 1
                    found = True
            if not found:
                allEthernetNodes.append([sourceIpAddress, 1])

    # Print all ethernet source address
    print("=== List of all used IP address ===")
    for node in allEthernetNodes:
        print(node)

    # find most used and print it
    mostUsed = [None, 0]
    for node in allEthernetNodes:
        if node[1] > mostUsed[1]:
            mostUsed = node

    print(f"Most used address {mostUsed[0]} with {mostUsed[1]} pakets")
    print("=============================================")


# INTERFACE
arp_communications()

# all_frames()

# userResponse = ""
# while userResponse != "q":
#     print("Actions list:")
#     print("1 - Get all frames")
#     print("2 - Most used IP address")
#     print("3 - All TFTP communications")
#     print("4 - All ARP communications")
#     print("q - Quit application")
#     print("----------------------------")
#     print("Type action > ", end="")
#     userResponse = input()
#     # userResponse = "1"
#     if userResponse == "1":
#         all_frames()
#     elif userResponse == "2":
#         most_used_ip_addresses()
#     elif userResponse == "3":
#         tftp_communications()
#     elif userResponse == "4":
#         arp_communications()
