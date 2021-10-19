from scapy.all import *


class Frame:
    db_protocols = None
    index = None
    hexPacket = None
    lengthPacket = None
    mediumLength = None

    destinationMacAddress = ""
    sourceMacAddress = ""

    sourceIpAddress = ""
    destinationIpAddress = ""

    endOfHead = None
    packetType = None
    protocol = None
    ipvProtocol = None

    sourcePort = None
    destinationPort = None

    def __init__(self, rawPacket, index, protocols):
        self.get_hex_from_raw(rawPacket)
        self.index = index
        self.db_protocols = protocols

        # calc everything
        self.calc_frame()

    def get_hex_from_raw(self, rawPacket):
        rawPacket = raw(rawPacket)
        self.hexPacket = rawPacket.hex()

    def print_hex(self):
        print("")
        for index, char in enumerate(self.hexPacket):
            print(char, end="")
            if index % 2:
                print(" ", end="")
            if index % 16 == 15:
                print(" ", end="")
            if index % 32 == 31:
                print("")

    def calculate_length(self):
        self.lengthPacket = int(len(self.hexPacket) / 2)
        mediumLength = self.lengthPacket + 4
        if mediumLength < 64:
            mediumLength = 64
        self.mediumLength = mediumLength

    def get_mac_addresses(self):
        # destination MAC address
        for b in range(0, 12):
            self.destinationMacAddress += self.hexPacket[b]
            if b % 2 != 0 and b != 11:
                self.destinationMacAddress += ":"

        # source MAC address
        for b in range(12, 24):
            self.sourceMacAddress += self.hexPacket[b]
            if b % 2 != 0 and b != 23:
                self.sourceMacAddress += ":"

    def print_frame(self):
        print(f"Rámec: {self.index}")
        print(f"PCAP API packet length: {self.lengthPacket}B")
        print(f"Real packet length: {self.mediumLength}B")
        print(self.packetType)
        print(f" -{self.protocol}")
        if self.sourceIpAddress:
            print(f" -Zdrojová IP adresa: {self.sourceIpAddress}")
            print(f" -Cieľová IP adresa: {self.destinationIpAddress}")
        print(f" -Zdrojová MAC adresa: {self.sourceMacAddress}")
        print(f" -Cieľová MAC adresa: {self.destinationMacAddress}")

        # print ports
        if self.ipvProtocol:
            if self.ipvProtocol == "TCP" or self.ipvProtocol == "UDP":
                print(self.ipvProtocol)
                sourcePort = int(self.hexPacket[self.endOfHead + 16:self.endOfHead + 20], 16)

                # print protocol by source port
                for xProtocol in self.db_protocols[9:]:
                    # print(xProtocol[1], sourcePort)
                    if int(xProtocol[1]) == sourcePort:
                        print("- " + xProtocol[2].replace("\n", ""))

                # print source and destination port
                print(" -Source port: " + str(self.sourcePort))
                print(" -Destination port: " + str(int(self.hexPacket[self.endOfHead + 20:self.endOfHead + 24], 16)))
        self.print_hex()
        print("\n------------------------------------------------")

    def calc_ethernet(self):
        self.packetType = "Ethernet II"
        self.protocol = self.hexPacket[24:28]

        for xProtocol in self.db_protocols:
            if xProtocol[0] == self.protocol:
                self.protocol = xProtocol[1].replace("\n", "")
        lengthHead = int(self.hexPacket[29]) * 4

        if self.protocol == "IPv4":
            self.endOfHead = 32 + lengthHead

            # Calculate source IP address
            self.sourceIpAddress = self.calc_ip_address(self.endOfHead)

            # Calculate destination IP address
            self.destinationIpAddress = self.calc_ip_address(self.endOfHead + 8)

            # get UDP, TCP, ..
            self.ipvProtocol = self.hexPacket[46:48]
            for xProtocol in self.db_protocols[7:]:
                if xProtocol[0] == self.ipvProtocol or xProtocol[1] == self.ipvProtocol:
                    self.ipvProtocol = xProtocol[2].replace("\n", "")

    def calc_ieee(self):
        # If it is not ethernet II, get another B to check
        packetHexForType = self.hexPacket[28:30]
        self.packetType = "IEEE 802.3"

        self.protocol = "LLC"
        for xProtocol in self.db_protocols[3:]:
            # print(xProtocol[1], sourcePort)
            if xProtocol[0] == packetHexForType:
                protocol = xProtocol[1].replace("\n", "")

    def calc_frame(self):
        # length calculation
        self.calculate_length()

        # mac addresses calculation
        self.get_mac_addresses()

        # calc packet ether type
        packetEtherTypeHex = self.hexPacket[24:28]

        # get product type
        if packetEtherTypeHex > "05DC":
            # Ethernet
            self.calc_ethernet()
        else:
            self.calc_ieee()

    def calc_ip_address(self, start_pointer):
        ip_address_hex = self.hexPacket[start_pointer:start_pointer + 8]
        ip_address = ""

        i = 0
        while i < len(ip_address_hex):
            ip_address += str(int(ip_address_hex[i] + ip_address_hex[i + 1], 16))
            if i + 2 != len(ip_address_hex):
                ip_address += ":"
            i += 2

        return ip_address
