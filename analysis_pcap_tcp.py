import struct
import dpkt
import sys


class Packet:
    def __init__(self, timestamp, buffer):
        self.buffer = buffer
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
        self.header_length = self.TCP[12] >> 2
        self.flags = self.TCP[12:14]
        a = self.flags[1]
        # From flag get ack, syn, fin, push
        self.ack = (0b10000 & int(a)) >> 4
        self.push = (0b1000 & int(a)) >> 3
        self.syn = (0b10 & int(a)) >> 1
        self.fin = 0b1 & int(a)
        self.windSizeValue = self.TCP[14:16]
        self.checksum = self.TCP[16:18]
        self.receiver_window_size = -1
        self.payload = self.buffer[66:len(buffer)]

    def __str__(self):
        return "Source IP: %s, Destination IP: %s, Source Port: %s, " "Destination Port: " \
               "%s, Sequence number: %s, Acknowledgement number: %s, Ack: %s, Syn: %s, Fin: %s, Receive Window " \
               "Size: %s " % (struct.unpack('>BBBB', self.sourceIP[:]), struct.unpack('>BBBB', self.destIP[:]),
                              str(int.from_bytes(self.sourcePort, "big")), str(int.from_bytes(self.destPort, "big")),
                              str(int.from_bytes(self.seqNum, "big")), str(int.from_bytes(self.ackNum, "big")),
                              self.ack, self.syn, self.fin, str(int.from_bytes(self.windSizeValue, "big")))

    def print(self):  # print sequence, ack num, window size for each flow in lists_of_flows
        return "Sequence number: %s, Acknowledgement Number: %s, Receive Window Size: %s" % \
               (str(int.from_bytes(self.seqNum, "big")), str(int.from_bytes(self.ackNum, "big")),
                str((int.from_bytes(self.windSizeValue, "big") << self.receiver_window_size)))


def find_packets(pcap):  # Goes read each element in the pcap file
    packets = []
    for timestamp, buffer in pcap:
        IP = buffer[14:34]
        if IP[9] == 6 and int.from_bytes(IP[12:16], "big") == 0x82f5910c or int.from_bytes(
                IP[16:20], "big") == 0x82f5910c:
            packet = Packet(timestamp, buffer)
            packets.append(packet)
    return packets


def find_flows(packets):
    list_of_flows = []
    receiver_window_size = -1
    for packet in packets:
        if packet.ack != 1 and packet.syn == 1:
            a = [packet]
            packet.receiver_window_size = int.from_bytes(packet.TCP[len(packet.TCP) - 1:len(packet.TCP)], "big")
            receiver_window_size = packet.receiver_window_size
            list_of_flows.insert(0, a)
        else:
            for flow in list_of_flows:
                port = flow[0].sourcePort
                if port == packet.destPort or port == packet.sourcePort:
                    packet.receiver_window_size = receiver_window_size
                    flow.append(packet)
                    break
    return list_of_flows


def going_through_flow(flow):
    sender = flow[0].sourceIP
    receiver = flow[0].destIP
    print("Port Number: ", str(int.from_bytes(flow[0].sourcePort, "big")))
    total_time = flow[len(flow) - 1].timestamp - flow[0].timestamp
    total_packets = 0
    counter = 0
    ack_counter = -1
    last_congestion_window = 1
    congestion_window_size = 0
    congestion_window_sizes = []
    triple_duk_ack = 0
    timeout = 0
    last_ack_num = 0
    second_to_last_ack_num = 0
    last_seq_num = int.from_bytes(flow[0].seqNum, "big")
    for packet in flow:
        if packet.sourceIP == sender and packet.destIP == receiver:
            congestion_window_size += 1
            if packet.syn == 0 and packet.ack == 1 and counter < 2:
                if packet.push == 0:
                    counter += 1
                    print("\t", packet.print())
            if last_seq_num > int.from_bytes(packet.seqNum, "big"):
                if last_ack_num == second_to_last_ack_num:
                    triple_duk_ack += 1
                else:
                    timeout += 1
            else:
                last_seq_num = int.from_bytes(packet.seqNum, "big")
            total_packets += len(packet.payload) + packet.header_length
        elif packet.sourceIP == receiver and packet.destIP == sender:
            last_congestion_window += -1
            second_to_last_ack_num = last_ack_num
            last_ack_num = int.from_bytes(packet.ackNum, "big")
            if 0 <= ack_counter < 2 and packet.ack == 1 and packet.syn == 0:
                print("\t\t ACK:", packet.print())
            ack_counter += 1
            if congestion_window_size > 0 and last_congestion_window == 0:
                last_congestion_window = congestion_window_size
                congestion_window_sizes.append(congestion_window_size)
                congestion_window_size = 0
    print("Sender Throughput: ", str(total_packets / total_time), " Bytes/sec")
    if len(congestion_window_sizes) < 6:
        print("Congestion window size:", congestion_window_sizes[1:])
    else:
        print("Congestion window size:", congestion_window_sizes[1: 6])
    print("Retransmission occurred due to triple duplicate ack: ", triple_duk_ack)
    print("Retransmission occurred due to timeout: ", timeout, "\n")


def main(pcap_file):
    file = open(pcap_file, "r+b")  # opens the file and is read only and binary
    pcap = dpkt.pcap.Reader(file)
    packets = find_packets(pcap)
    list_of_flows = find_flows(packets)
    print("The number of TCP flows initiate from the sender", len(list_of_flows), "\n")
    for flow in list_of_flows:  # part 2 of A: print sequence, ack num, window size for each flow in lists_of_flows
        going_through_flow(flow)


if __name__ == '__main__':
    name = sys.argv[1]
    if ".pcap" in name:
        main(name)
    else:
        print("Not a valid file! (need a pcap file)")
