from scapy.all import *

# load files and create db
data = rdpcap('vzorky/trace-5.pcap')
file = open('db.txt', "r")
protocols = []
for iProtocol in file:
    protocols.append(iProtocol.split(" "))


def print_frame(index, packet):
    sourceIpAddress = None
    ipvProtocol = None

    rawPacket = raw(packet)
    hexPacket = rawPacket.hex()

    # length calculation
    lengthPacket = int(len(hexPacket) / 2)
    mediumLength = lengthPacket + 4
    if mediumLength < 64:
        mediumLength = 64

    # going through parts of packet
    # destination mac address
    destinationMacAddress = ""
    for b in range(0, 12):
        destinationMacAddress += hexPacket[b]
        if b % 2 != 0 and b != 11:
            destinationMacAddress += ":"

    # destination source address
    sourceMacAddress = ""
    for b in range(12, 24):
        sourceMacAddress += hexPacket[b]
        if b % 2 != 0 and b != 23:
            sourceMacAddress += ":"

    # packet ether type
    packetEtherType = hexPacket[24:28]
    protocol = hexPacket[24:28]

    # get product type
    if packetEtherType > "05DC":
        # Ethernet
        packetType = "Ethernet II"
        for xProtocol in protocols:
            if xProtocol[0] == protocol:
                protocol = xProtocol[1].replace("\n", "")
        lengthHead = int(hexPacket[29]) * 4

        # Calculate source IP address
        endOfHead = 32 + lengthHead
        sourceIpAddressHex = hexPacket[endOfHead:endOfHead + 8]
        sourceIpAddress = ""
        i = 0
        while i < len(sourceIpAddressHex):
            sourceIpAddress += str(int(sourceIpAddressHex[i] + sourceIpAddressHex[i + 1], 16))
            if i + 2 != len(sourceIpAddressHex):
                sourceIpAddress += ":"
            i += 2

        # Calculate destination IP address
        destinationIpAddressHex = hexPacket[endOfHead + 8:endOfHead + 16]
        destinationIpAddress = ""
        i = 0
        while i < len(destinationIpAddressHex):
            destinationIpAddress += str(int(destinationIpAddressHex[i] + destinationIpAddressHex[i + 1], 16))
            if i + 2 != len(destinationIpAddressHex):
                destinationIpAddress += ":"
            i += 2

        # get UDP, TCP, ..
        ipvProtocol = hexPacket[46:48]
        for xProtocol in protocols[7:]:
            if xProtocol[0] == ipvProtocol or xProtocol[1] == ipvProtocol:
                ipvProtocol = xProtocol[2].replace("\n", "")

    else:
        # If it is not ethernet II, get another B to check
        packetHexForType = hexPacket[28:30]
        packetType = "IEEE 802.3"

        protocol = "LLC"
        for xProtocol in protocols[3:]:
            # print(xProtocol[1], sourcePort)
            if xProtocol[0] == packetHexForType:
                protocol = xProtocol[1].replace("\n", "")

    # print all data
    print(f"Rámec: {index + 1}")
    print(f"PCAP API packet length: {lengthPacket}B")
    print(f"Real packet length: {mediumLength}B")
    print(packetType)
    print(f" -{protocol}")
    if sourceIpAddress:
        print(f" -Zdrojová IP adresa: {sourceIpAddress}")
        print(f" -Cieľová IP adresa: {destinationIpAddress}")
    print(f" -Zdrojová MAC adresa: {sourceMacAddress}")
    print(f" -Cieľová MAC adresa: {destinationMacAddress}")

    # print ports
    if ipvProtocol:
        if ipvProtocol == "TCP" or ipvProtocol == "UDP":
            print(ipvProtocol)
            sourcePort = int(hexPacket[endOfHead + 16:endOfHead + 20], 16)

            # print protocol by source port
            for xProtocol in protocols[9:]:
                # print(xProtocol[1], sourcePort)
                if int(xProtocol[1]) == sourcePort:
                    print("- " + xProtocol[2].replace("\n", ""))

            # print source and destination port
            print(" -Source port: " + str(sourcePort))
            print(" -Destination port: " + str(int(hexPacket[endOfHead + 20:endOfHead + 24], 16)))

    # print hex packet
    print("")
    for index, char in enumerate(hexPacket):
        print(char, end="")
        if index % 2:
            print(" ", end="")
        if index % 16 == 15:
            print(" ", end="")
        if index % 32 == 31:
            print("")
    print("\n------------------------------------------------")

    return sourceIpAddress


def all_frames():
    allEthernetNodes = []
    for index, packet in enumerate(data):
        sourceIpAddress = print_frame(index, packet)

        # Add source address to array if not exist. If yes.. Increase number of usage
        found = False
        for node in allEthernetNodes:
            if node[0] == sourceIpAddress:
                node[1] += 1
                found = True
        if not found:
            allEthernetNodes.append([sourceIpAddress, 1])

    # Print all ethernet source address
    print("Zoznam IP adries všetkých odosielajúcich uzlov:")
    for node in allEthernetNodes:
        print(node[0])

    # find most used and print it
    mostUsed = [None, 0]
    for node in allEthernetNodes:
        if node[1] > mostUsed[1]:
            mostUsed = node

    print(f"Najviac bola pouzivana adresa {mostUsed[0]} s {mostUsed[1]} paketmy")


print("Choose your action:")
print("1 - Get all frames")
# userResponse = input()
userResponse = "1"
print(userResponse)
if userResponse == "1":
    all_frames()
