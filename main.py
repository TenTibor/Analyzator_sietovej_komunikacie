from ast import literal_eval

from scapy.all import *

# load files and create db
data = rdpcap('vzorky/eth-9.pcap')
file = open('db.txt', "r")
protocols = []
for iProtocol in file:
    protocols.append(iProtocol.split(" "))

for index, packet in enumerate(data):
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
        lengthHead = int(hexPacket[29]) * 4  # why tf 4?

        # Calculate source IP adress
        endOfHead = 32 + lengthHead
        sourceIpAddressHex = hexPacket[endOfHead:endOfHead + 8]
        sourceIpAddress = ""
        i = 0
        while i < len(sourceIpAddressHex):
            sourceIpAddress += str(int(sourceIpAddressHex[i] + sourceIpAddressHex[i + 1], 16))
            if i + 2 != len(sourceIpAddressHex):
                sourceIpAddress += ":"
            i += 2

        # Calculate destination IP adress
        destinationIpAddressHex = hexPacket[endOfHead + 8:endOfHead + 16]
        destinationIpAddress = ""
        i = 0
        while i < len(destinationIpAddressHex):
            destinationIpAddress += str(int(destinationIpAddressHex[i] + destinationIpAddressHex[i + 1], 16))
            if i + 2 != len(destinationIpAddressHex):
                destinationIpAddress += ":"
            i += 2

        # get protocol
        ipvProtocol = hexPacket[46:48]
        for xProtocol in protocols:
            if xProtocol[0] == ipvProtocol or xProtocol[1] == ipvProtocol:
                ipvProtocol = xProtocol[2].replace("\n", "")

    else:
        # If it is not ethernet II, get another B to check
        packetHexForType = hexPacket[28:30]
        if packetHexForType == "aa":
            packetType = "IEEE 802.3 - Snap"
        elif packetHexForType == "ff":
            packetType = "IEEE 802.3 - Raw"
        else:
            packetType = "IEEE 802.3 - LLC"

    # print all data
    print(f"Rámec: {index + 1}")
    print(f"Dĺžka rámca poskytnutá pcap API - {lengthPacket} B")
    print(f"Dĺžka rámca prenášaného po médiu - {mediumLength} B")
    print(f"Typ: {packetType}")
    print(f"Protocol: {protocol}")
    print(f"Zdrojová IP adresa: {sourceIpAddress}")
    print(f"Cieľová IP adresa: {destinationIpAddress}")
    print(f"Zdrojová MAC adresa: {sourceMacAddress}")
    print(f"Cieľová MAC adresa: {destinationMacAddress}")

    # print ports
    print(ipvProtocol)
    if ipvProtocol == "TCP" or ipvProtocol == "UDP":
        print("Source port: " + str(int(hexPacket[endOfHead + 16:endOfHead + 20], 16)))
        print("Destination port: " + str(int(hexPacket[endOfHead + 20:endOfHead + 24], 16)))

    # print hex packet
    for index, char in enumerate(hexPacket):
        print(char, end="")
        if index % 2:
            print(" ", end="")
        if index % 16 == 15:
            print(" ", end="")
        if index % 32 == 31:
            print("")
    print("\n")
