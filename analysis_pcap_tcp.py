import dpkt


# a packet that contains the timestamp and information encapsulated in Ethernet
class Packet:
    def __init__(self, timestamp, eth):
        self.ts = timestamp
        self.eth = eth


# calculates the throughput from the first packet sent after the handshake to the FIN sent by the receiver
def calculate_throughput(num):
    data_sent_over_flow = 0
    for pkt in flows[num]:
        tcp_size = len(pkt.data.data)  # length of TCP segment
        data_sent_over_flow = data_sent_over_flow + tcp_size
    return 0


# calculate scaling factor
def calculate_scaling_factor(num):
    parsed_opt = dpkt.tcp.parse_opts(flows[num][0].eth.data.data.opts)
    shift_count = parsed_opt[5][1]
    scaling_factor = 2 ** int.from_bytes(shift_count, byteorder='big')
    return scaling_factor


# sorts the packets into respective flows organized in the form of lists
def sort_flows(packet):
    # base case
    if len(flows[0]) == 0:
        flows[0].append(packet)
        return
    id_to_test = [get_ip(packet.eth.data.src), packet.eth.data.data.sport, get_ip(packet.eth.data.dst), packet.eth.data.data.dport]
    for id_to_compare in flow_ids:
        if id_to_test == id_to_compare or [id_to_test[2],id_to_test[3],id_to_test[0],id_to_test[1]] == id_to_compare:
            flows[flow_ids.index(id_to_compare)].append(packet)
            return


# adds flow to list of streams if not there before
def identify_streams(ip, tcp):
    flow_index = [get_ip(ip.src), tcp.sport, get_ip(ip.dst), tcp.dport]
    if len(flow_ids) == 0:
        flow_ids.append(flow_index)
    else:
        unique_flow_flag = True
        for flow in flow_ids:
            if flow == flow_index:
                unique_flow_flag = False
        if unique_flow_flag:
            flow_ids.append(flow_index)
    filter_flows()


# communication from Host A on Port a to Host B on Port b is the same flow as Host B on Port b to Host A on Port a
def filter_flows():
    for flow in flow_ids:
        reverse_order = [flow[2], flow[3], flow[0], flow[1]]
        for s in flow_ids:
            if reverse_order == s:
                flow_ids.remove(s)


# returns the source/destination IP address
def get_ip(ip_in_hex):
    new_ip = ''
    for num in ip_in_hex:
        new_ip = new_ip + str(num) + "."

    new_ip = new_ip[0:new_ip.__len__() - 1]
    return new_ip


# checks if SYN ACK exists
def check_flows(tcp_to_check):
    syn_flag = (tcp_to_check.flags & dpkt.tcp.TH_SYN) != 0
    ack_flag = (tcp_to_check.flags & dpkt.tcp.TH_ACK) != 0
    if syn_flag and ack_flag:
        return True
    else:
        return False


# reads the packets listed in pcap file
def analyze_pcap_tcp():
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        packet = Packet(ts, eth)
        unsorted_packet.append(packet)
        ip = eth.data
        tcp = ip.data
        if check_flows(tcp):
            flows.append([])
        identify_streams(ip, tcp)


unsorted_packet = []
flows = []
flow_ids = []

file_name = 'assignment2.pcap'  # sys.argv[1]
f = open(file_name, 'rb')
pcap = dpkt.pcap.Reader(f)

analyze_pcap_tcp()

print(len(flow_ids))
print(flow_ids)

for pkt in unsorted_packet:
    sort_flows(pkt)
print(flows[0][4].eth.data.data.seq)
print(flows[0][4].eth.data.data.ack)

print(unsorted_packet.__len__())
print(len(flows[0]))
print(len(flows[1]))
print(len(flows[2]))

print(str(len(flows)) + " TCP flows initiated from sender")
for id in flow_ids:
    num = flow_ids.index(id)
    print(flows[num][0].ts)
    scaling_factor = calculate_scaling_factor(num)
    print("Source: " + flow_ids[num][0] + " at Port: " + str(flow_ids[num][1]) + " | Destination: " + flow_ids[num][2] + " at Port: " + str(flow_ids[num][3]))
    print("\tTransaction 1: Sequence Number = " + str(flows[num][3].eth.data.data.seq))
    print("\t               Acknowledgement Number = " + str(flows[num][3].eth.data.data.ack))
    print("\t               Receive Window Size = " + str(flows[num][3].eth.data.data.win * scaling_factor))
    print("\tTransaction 2: Sequence Number = " + str(flows[num][4].eth.data.data.seq))
    print("\t               Acknowledgement Number = " + str(flows[num][4].eth.data.data.ack))
    print("\t               Receive Window Size = " + str(flows[num][4].eth.data.data.win * scaling_factor) + "\n")

f.close()
