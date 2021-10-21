from scapy.all import *

flags = {
    "01": "FIN",
    "02": "SYN",
    "04": "RST",
    "12": "SYN, ACK",
    "10": "ACK",
    "11": "FIN, ACK",
    "14": "RST, ACK",
    "18": "PSH, ACK",
    "19": "FIN, PSH, ACK",
    "40": "Don't fragmet"
}


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
    frameType = None
    packetType = None
    transportProtocol = None
    protocol_by_port = None

    sourcePort = None
    destinationPort = None

    flag = None

    # ARP
    op_code = None
    sender_ip_address = None
    target_ip_address = None

    # ICMP
    icmp_type = None
    icmp_code = None

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
        print(f"API packet length: {self.lengthPacket} B")
        print(f"Real packet length: {self.mediumLength} B")
        print(f"Source MAC address: {self.sourceMacAddress}")
        print(f"Destination MAC address: {self.destinationMacAddress}")
        print(self.frameType)
        print(f" -{self.packetType}")

        if self.transportProtocol:
            print(f"  -Source IP address: {self.sourceIpAddress}")
            print(f"  -Destination IP address: {self.destinationIpAddress}")

            print(" -" + self.transportProtocol)

            # print ICMP
            if self.icmp_type is not None:
                print("  -" + self.icmp_type)
                if self.icmp_code is not None:
                    print("   -" + self.icmp_code)

            # print ports
            if self.protocol_by_port:
                print("  -" + self.protocol_by_port)

            # print flag
            if self.flag:
                print("   -" + self.flag)

            # print source and destination port
            if self.sourcePort:
                print("   -Source port: " + str(self.sourcePort))
                print("   -Destination port: " + str(self.destinationPort))

        if self.packetType == "ARP":
            print("  -Opcode: " + ("Request" if self.op_code == 1 else "Reply"))
            print("  -Sender IP address: " + self.sender_ip_address)
            print("  -Target IP address: " + self.target_ip_address)
        self.print_hex()
        print("\n------------------------------------------------")

    def export_to_string(self):
        output = ""
        output += f"Frame: {self.index}\n"
        output += f"PCAP API packet length: {self.lengthPacket} B\n"
        output += f"Real packet length: {self.mediumLength} B\n"
        output += f"Source MAC address: {self.sourceMacAddress}\n"
        output += f"Destination MAC address: {self.destinationMacAddress}\n"
        output += self.frameType + "\n"
        output += f" -{self.packetType}\n"

        if self.transportProtocol:
            output += f"  -Source IP address: {self.sourceIpAddress}\n"
            output += f"  -Destination IP address: {self.destinationIpAddress}\n"
            output += " -" + self.transportProtocol + "\n"

            # print ICMP
            if self.icmp_type is not None:
                output += ("  -" + self.icmp_type + "\n")
                if self.icmp_code is not None:
                    output += ("   -" + self.icmp_code + "\n")

            # print ports
            if self.protocol_by_port:
                output += ("  -" + self.protocol_by_port + "\n")

            # print flag
            if self.flag:
                output += ("   -" + self.flag + "\n")

            # print source and destination port
            if self.sourcePort:
                output += "   -Source port: " + str(self.sourcePort) + "\n"
                output += "   -Destination port: " + str(self.destinationPort) + "\n"

        if self.packetType == "ARP":
            output += "  -Opcode: " + ("Request" if self.op_code == 1 else "Reply") + "\n"
            output += "  -Sender IP address: " + self.sender_ip_address + "\n"
            output += "  -Target IP address: " + self.target_ip_address + "\n"

        # generate hex
        output += "\n"
        for index, char in enumerate(self.hexPacket):
            output += char
            if index % 2:
                output += " "
            if index % 16 == 15:
                output += " "
            if index % 32 == 31:
                output += "\n"

        output += "\n------------------------------------------------" + "\n"
        return output

    def calc_ethernet(self):
        self.frameType = "Ethernet II"
        self.packetType = self.hexPacket[24:28]

        for xProtocol in self.db_protocols:
            if xProtocol[0] == self.packetType:
                self.packetType = xProtocol[1].replace("\n", "")
        # lengthHead = int(self.hexPacket[28:29]) * 4

        if self.packetType == "IPv4":
            self.endOfHead = 52

            # Calculate source IP address
            self.sourceIpAddress = self.calc_ip_address_from_hex(self.endOfHead)

            # Calculate destination IP address
            self.destinationIpAddress = self.calc_ip_address_from_hex(self.endOfHead + 8)

            # get UDP, TCP, ..
            self.transportProtocol = self.hexPacket[46:48]
            for xProtocol in self.db_protocols[9:]:
                if xProtocol[0] == self.transportProtocol or xProtocol[1] == self.transportProtocol:
                    self.transportProtocol = xProtocol[2].replace("\n", "")

                    # set protocols if TCP or UDP
                    if self.transportProtocol == "TCP" or self.transportProtocol == "UDP":
                        self.sourcePort = int(self.hexPacket[self.endOfHead + 16:self.endOfHead + 20], 16)
                        self.destinationPort = int(self.hexPacket[self.endOfHead + 20:self.endOfHead + 24], 16)

                        # print protocol by destination port
                        for yProtocol in self.db_protocols[12:]:
                            if int(yProtocol[1]) == self.destinationPort or int(yProtocol[1]) == self.sourcePort:
                                self.protocol_by_port = yProtocol[2].replace("\n", "")

                    if self.transportProtocol == "TCP":
                        self.flag = flags[self.hexPacket[94:96]]

            # calc ICMP protocol
            if self.transportProtocol == "ICMP":
                icmp_type_hex = self.hexPacket[68:70]
                icmp_data = self.load_icmp_data()

                for row in icmp_data[:16]:
                    if row[0] == icmp_type_hex:
                        self.icmp_type = row[1].replace("\n", "")

                        # check code
                        if icmp_type_hex == "03":
                            for rowB in icmp_data[17:31]:
                                if rowB[0] == icmp_type_hex:
                                    self.icmp_code = rowB[1].replace("\n", "")
                        elif icmp_type_hex == "05":
                            for rowB in icmp_data[32:36]:
                                if rowB[0] == icmp_type_hex:
                                    self.icmp_code = rowB[1].replace("\n", "")
                        elif icmp_type_hex == "11":
                            for rowB in icmp_data[37:39]:
                                if rowB[0] == icmp_type_hex:
                                    self.icmp_code = rowB[1].replace("\n", "")
                        elif icmp_type_hex == "12":
                            for rowB in icmp_data[40:]:
                                if rowB[0] == icmp_type_hex:
                                    self.icmp_code = rowB[1].replace("\n", "")

        if self.packetType == "ARP":
            # Calculate source & destination IP address
            self.sourceIpAddress = self.calc_ip_address_from_hex(56)
            self.destinationIpAddress = self.calc_ip_address_from_hex(66)
            # get op code
            self.op_code = int(self.hexPacket[43], 16)
            # get source and target IP address
            self.sender_ip_address = self.calc_ip_address_from_hex(56)
            self.target_ip_address = self.calc_ip_address_from_hex(76)

    def calc_ieee(self):
        # If it is not ethernet II, get another B to check
        packetHexForType = self.hexPacket[28:30]
        self.frameType = "IEEE 802.3"

        self.packetType = "LLC"
        for xProtocol in self.db_protocols[5:]:
            if xProtocol[0] == packetHexForType:
                self.packetType = xProtocol[1].replace("\n", "")

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
                ip_address += "."
            i += 2

        return ip_address

    def load_icmp_data(self):
        file = open('icmp.txt', "r")
        data = []
        for iProtocol in file:
            data.append(iProtocol.split(" "))
        return data
