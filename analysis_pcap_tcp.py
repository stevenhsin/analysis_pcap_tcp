import dpkt


# a packet that contains the timestamp and information encapsulated in Ethernet
class Packet:
    def __init__(self, timestamp, eth):
        self.ts = timestamp
        self.eth = eth


# prints out the first five congestion window values if possible
def print_first_five_cwinds(num, rtt):
    ts_lower_bound = flows[num][3].ts
    ts_upper_bound = flows[num][3].ts + rtt
    ceiling = flows[num][len(flows[num]) - 1].ts
    for i in range(0, 5):
        packets_in_window = 0
        last_pkt = flows[num][3]
        if ts_upper_bound <= ceiling:
            for pkt in flows[num]:
                if ts_lower_bound <= pkt.ts < ts_upper_bound:
                    packets_in_window = packets_in_window + 1
                    last_pkt = pkt
            print(packets_in_window)
            ts_lower_bound = ts_lower_bound
            for ack_pkt in flows[num]:
                if ack_pkt.eth.data.data.ack == last_pkt.eth.data.data.seq + len(last_pkt.eth.data.data.data):
                    rtt = calculate_new_rtt(rtt, ack_pkt.ts - last_pkt.ts)
                    break
            ts_upper_bound = ts_upper_bound + rtt
        elif ts_upper_bound > ceiling and i < 3:
            for pkt in flows[num]:
                if ts_lower_bound <= pkt.ts <= ceiling:
                    packets_in_window = packets_in_window + 1
            print(packets_in_window)
            break
        else:
            break


# calculate the new RTT given old RTT and the time between the sender sending a packet and the acknowledgement
def calculate_new_rtt(old_rtt, new_rtt):
    return 0.875 * old_rtt + 0.125 * new_rtt


# calculates the throughput from the first packet sent after the handshake to the FIN sent by the receiver
def calculate_throughput(num):
    # TODO: might change depending on which FIN I use, right now determined based on FIN sent by receiver
    start_ts = flows[num][0].ts
    end_ts = flows[num][len(flows[num]) - 2].ts
    diff_ts = end_ts - start_ts
    data_sent_over_flow = 0
    for pkt in flows[num]:
        tcp_size = len(pkt.eth.data.data)  # length of TCP segment
        data_sent_over_flow = data_sent_over_flow + tcp_size
    data_sent_over_flow = data_sent_over_flow - len(flows[num][len(flows[num]) - 1].eth.data.data)
    throughput = float(data_sent_over_flow)/diff_ts
    # print(start_ts)
    # print(end_ts)
    # print(diff_ts)
    # print(data_sent_over_flow)
    return throughput


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
def read_pcap_tcp():
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
read_pcap_tcp()
# sorting the packets into flows
for pkt in unsorted_packet:
    sort_flows(pkt)

print(str(len(flows)) + " TCP flows initiated from sender")
for id in flow_ids:
    print("____________________________________________________________________________________\n")
    num = flow_ids.index(id)
    scaling_factor = calculate_scaling_factor(num)
    throughput = calculate_throughput(num)
    # TODO: Explain in documentation that the corresponding response from receiver was done by adding length of
    # TODO: the data to SEQ number of sender to get the SEQ of the next expected packet
    print("Source: " + flow_ids[num][0] + " at Port: " + str(flow_ids[num][1]) + " | Destination: " + flow_ids[num][2] + " at Port: " + str(flow_ids[num][3]))
    print("Throughput: " + str(throughput) + " bytes per second")
    print("\n\tTransaction 1: " + flow_ids[num][0] + " to " + flow_ids[num][2])
    print("\t          Sequence Number = " + str(flows[num][4].eth.data.data.seq))
    print("\t          Acknowledgement Number = " + str(flows[num][4].eth.data.data.ack))
    print("\t          Receive Window Size = " + str(flows[num][4].eth.data.data.win * scaling_factor))
    rtt_calc_start = flows[num][4].ts
    rtt_calc_end = 0
    for pkt in flows[num]:
        if pkt.eth.data.data.ack == flows[num][4].eth.data.data.seq + len(flows[num][4].eth.data.data.data):
            rtt_calc_end = pkt.ts
            print("\tTransaction 1: " + flow_ids[num][2] + " to " + flow_ids[num][0])
            print("\t          Sequence Number = " + str(pkt.eth.data.data.seq))
            print("\t          Acknowledgement Number = " + str(pkt.eth.data.data.ack))
            print("\t          Receive Window Size = " + str(pkt.eth.data.data.win * scaling_factor) + "\n")
    print("\tTransaction 2: " + flow_ids[num][0] + " to " + flow_ids[num][2])
    print("\t          Sequence Number = " + str(flows[num][5].eth.data.data.seq))
    print("\t          Acknowledgement Number = " + str(flows[num][5].eth.data.data.ack))
    print("\t          Receive Window Size = " + str(flows[num][5].eth.data.data.win * scaling_factor))
    for pkt in flows[num]:
        if pkt.eth.data.data.ack == flows[num][5].eth.data.data.seq + len(flows[num][5].eth.data.data.data):
            print("\tTransaction 2: " + flow_ids[num][2] + " to " + flow_ids[num][0])
            print("\t          Sequence Number = " + str(pkt.eth.data.data.seq))
            print("\t          Acknowledgement Number = " + str(pkt.eth.data.data.ack))
            print("\t          Receive Window Size = " + str(pkt.eth.data.data.win * scaling_factor) + "\n")
    rtt_calc = rtt_calc_end - rtt_calc_start
    print("RTT: " + str(rtt_calc))
    print("Using RTT of first transaction:")
    print_first_five_cwinds(num, rtt_calc)

    # probably will use handshake RTT
    test = flows[num][2].ts - flows[num][0].ts
    print("Handshake RTT: " + str(test))
    print("Using Handshake RTT: ")
    print_first_five_cwinds(num, test)

    waverage = calculate_new_rtt(test, rtt_calc)
    print("Average RTT: " + str(waverage))
    print("Using Weighed Average:")
    print_first_five_cwinds(num, waverage)

f.close()
