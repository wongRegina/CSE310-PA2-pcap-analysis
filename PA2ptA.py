import struct
import dpkt


class Packet:
    def __init__(self, timestamp, buffer):
        self.timestamp = timestamp
        # First 28 bytes are Ethernet II - buffer[0,14]
        self.Ethernet = buffer[0:14]
        # Next 40 bytes are Internet Protocol(IP) - buffer [14,34]
        self.IP = buffer[14:34]
        # Going through the data of the IP
        self.timeToLive = self.IP[8]
        self.protocol = self.IP[9]
        self.sourceIP = self.IP[12:16]
        self.destIP = self.IP[16:20]
        # The last bytes are Transmission Control Protocol(TCP) - buffer[34-buffer.size]
        self.TCP = buffer[34:len(buffer)]
        # Going through the data of the TCP
        self.sourcePort = self.TCP[0:2]
        self.destPort = self.TCP[2:4]
        self.seqNum = self.TCP[4:8]
        self.ackNum = self.TCP[8:12]
        self.flags = self.TCP[12:14]
        a = (self.flags)[1]
        # From flag get ack, syn, fin
        self.ack = (0b10000 & int(a)) >> 4
        self.syn = (0b10 & int(a)) >> 1
        self.fin = 0b1 & int(a)
        self.windSizeValue = self.TCP[14:16]
        self.checksum = self.TCP[16:18]

    def __str__(self):
        return "Source IP: %s, Destination IP: %s, Source Port: %s, " "Destination Port: " \
               "%s, Sequence number: %s, Acknowledgement number: %s, Ack: %s, Syn: %s, Fin: %s, Receive Window " \
               "Size: %s " % (struct.unpack('>BBBB', self.sourceIP[:]), str(int.from_bytes(self.destIP, "big")),
                              str(int.from_bytes(self.sourcePort, "big")), str(int.from_bytes(self.destPort, "big")),
                              str(int.from_bytes(self.seqNum, "big")), str(int.from_bytes(self.ackNum, "big")),
                              self.ack, self.syn, self.fin, str(int.from_bytes(self.windSizeValue, "big")))


def find_packets(pcap):  # Goes read each element in the pcap file
    packets = []
    for timestamp, buffer in pcap:
        packet = Packet(timestamp, buffer)
        packets.append(packet)
    return packets


def find_TCP_connections(packets):
    num_of_TCP_connections = 0
    for packet in packets:
        # print(packet.seqNum, packet.ackNum)
        if packet.syn == 1 and packet.ack == 1:
            num_of_TCP_connections += 1
    # print(num_of_TCP_connections)
    return num_of_TCP_connections


def main():
    file = open("assignment2.pcap", "r+b")  # opens the file and is read only and binary
    pcap = dpkt.pcap.Reader(file)
    packets = find_packets(pcap)
    counter = 0
    for packet in packets:
        print(packet)
        # if counter < 50:
        #     # a
        # else:
        #     break
        # counter += 1
    print("The number of TCP flows initiate from the sender", find_TCP_connections(packets))


if __name__ == '__main__':
    main()
