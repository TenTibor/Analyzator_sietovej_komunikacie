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
    protocol_by_port = None

    sourcePort = None
    destinationPort = None

    op_code = None
    sender_ip_address = None
    target_ip_address = None

    def __repr__(self):
        return str(self.index)

    def __init__(self, rawPacket, index, protocols):
        self.get_hex_from_raw(rawPacket)
        self.index = index
        self.db_protocols = protocols

        # calc everything
        self.calc_whole_frame()

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
        print(f"Frame: {self.index}")
        print(f"PCAP API packet length: {self.lengthPacket}B")
        print(f"Real packet length: {self.mediumLength}B")
        print(f"Zdrojová MAC adresa: {self.sourceMacAddress}")
        print(f"Cieľová MAC adresa: {self.destinationMacAddress}")
        print(self.packetType)
        print(f" -{self.protocol}")

        if self.ipvProtocol:
            print(f" -Zdrojová IP adresa: {self.sourceIpAddress}")
            print(f" -Cieľová IP adresa: {self.destinationIpAddress}")

            print(self.ipvProtocol)
            # print ports
            if self.protocol_by_port:
                print(self.protocol_by_port, end="")

            # print source and destination port
            if self.sourcePort:
                print(" -Source port: " + str(self.sourcePort))
                print(" -Destination port: " + str(self.destinationPort))

        if self.protocol == "ARP":
            print("  -Opcode: " + ("Request" if self.op_code == 1 else "Reply"))
            print("  -Sender IP address: " + self.sender_ip_address)
            print("  -Target IP address: " + self.target_ip_address)

        print("\n------------------------------------------------")

    def calc_ethernet(self):
        self.packetType = "Ethernet II"
        self.protocol = self.hexPacket[24:28]

        for xProtocol in self.db_protocols:
            if xProtocol[0] == self.protocol:
                self.protocol = xProtocol[1].replace("\n", "")
        # lengthHead = int(self.hexPacket[28:29]) * 4

        if self.protocol == "IPv4":
            self.endOfHead = 52

            # Calculate source IP address
            self.sourceIpAddress = self.calc_ip_address_from_hex(self.endOfHead)

            # Calculate destination IP address
            self.destinationIpAddress = self.calc_ip_address_from_hex(self.endOfHead + 8)

            # get UDP, TCP, ..
            self.ipvProtocol = self.hexPacket[46:48]
            for xProtocol in self.db_protocols[8:]:
                if xProtocol[0] == self.ipvProtocol or xProtocol[1] == self.ipvProtocol:
                    self.ipvProtocol = xProtocol[2].replace("\n", "")

                    # set protocols if TCP or UDP
                    if self.ipvProtocol == "TCP" or self.ipvProtocol == "UDP":
                        self.sourcePort = int(self.hexPacket[self.endOfHead + 16:self.endOfHead + 20], 16)
                        self.destinationPort = int(self.hexPacket[self.endOfHead + 20:self.endOfHead + 24], 16)

                        # print protocol by destination port
                        for yProtocol in self.db_protocols[11:]:
                            # print(xProtocol[1], sourcePort)
                            if int(yProtocol[1]) == self.destinationPort:
                                self.protocol_by_port = yProtocol[2]

        if self.protocol == "ARP":
            # Calculate source & destination IP address
            self.sourceIpAddress = self.calc_ip_address_from_hex(56)
            self.destinationIpAddress = self.calc_ip_address_from_hex(66)
            # get op code
            self.op_code = int(self.hexPacket[43], 16)
            # get source and target IP address
            self.sender_ip_address = self.calc_ip_address_from_hex(56)
            self.target_ip_address = self.calc_ip_address_from_hex(76)

            #

    def calc_ieee(self):
        # If it is not ethernet II, get another B to check
        packetHexForType = self.hexPacket[28:30]
        self.packetType = "IEEE 802.3"

        self.protocol = "LLC"
        for xProtocol in self.db_protocols[4:]:
            # print(xProtocol[1], sourcePort)
            if xProtocol[0] == packetHexForType:
                protocol = xProtocol[1].replace("\n", "")

    def calc_whole_frame(self):
        # length calculation
        self.calculate_length()

        # mac addresses calculation
        self.get_mac_addresses()

        # calc packet ether type
        packetEtherTypeHex = self.hexPacket[24:28]

        # get product type
        if packetEtherTypeHex >= "05DC":
            # Ethernet
            self.calc_ethernet()
        else:
            self.calc_ieee()

    def calc_ip_address_from_hex(self, start_pointer):
        ip_address_hex = self.hexPacket[start_pointer:start_pointer + 8]
        ip_address = ""

        i = 0
        while i < len(ip_address_hex):
            ip_address += str(int(ip_address_hex[i] + ip_address_hex[i + 1], 16))
            if i + 2 != len(ip_address_hex):
                ip_address += ":"
            i += 2

        return ip_address
