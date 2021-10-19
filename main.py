from scapy.all import *

from frame import Frame

# load files and create db
file = "trace-5.pcap"
data = rdpcap('vzorky/' + file)
print(f"[File '{file}' was loaded]\n")
file = open('db.txt', "r")
protocols = []
for iProtocol in file:
    protocols.append(iProtocol.split(" "))


def tftp_communications():
    pass


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

        # print frame
        this_frame.print_frame()

        # get source ip from frame
        sourceIpAddress = this_frame.sourceIpAddress

        # Add source address to array if not exist. If yes.. Increase number of usage
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
        print(node[0])

    # find most used and print it
    mostUsed = [None, 0]
    for node in allEthernetNodes:
        if node[1] > mostUsed[1]:
            mostUsed = node

    print(f"Most used address {mostUsed[0]} with {mostUsed[1]} pakets")


# INTERFACE
userResponse = ""
while userResponse != "q":
    print("Actions list:")
    print("1 - Get all frames")
    print("2 - Most used IP address")
    print("3 - All TFTP communications")
    print("q - Quit application")
    print("----------------------------")
    print("Type action > ", end="")
    userResponse = input()
    # userResponse = "1"
    print(userResponse)
    if userResponse == "1":
        all_frames()
    elif userResponse == "2":
        most_used_ip_addresses()
    elif userResponse == "3":
        tftp_communications()
