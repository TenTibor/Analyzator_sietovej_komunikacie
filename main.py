from scapy.all import *

# load one vzorku
data = rdpcap('vzorky/trace-2.pcap')

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

    # get product type
    if packetEtherType > "05DC":
        packetType = "Ethernet II"
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
    print(f"Rámec: {index+1}")
    print(f"Dĺžka rámca poskytnutá pcap API - {lengthPacket} B")
    print(f"Dĺžka rámca prenášaného po médiu - {mediumLength} B")
    print(f"Typ: {packetType}")
    print(f"Zdrojová MAC adresa: {sourceMacAddress}")
    print(f"Cieľová MAC adresa: {destinationMacAddress}")

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
