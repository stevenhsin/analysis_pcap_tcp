import dpkt


# calculates the throughput from the first packet sent after the handshake to the FIN sent by the receiver
def calculate_throughput():
    return 0


# sorts the packets into respective flows organized in the form of lists
def sort_flows(eth):
    # base case
    if len(flows[0]) == 0:
        flows[0].append(eth)
        return
    port = eth.data.data.sport
    if port == 80:
        port = eth.data.data.dport
    ports_to_compare = []
    for flow in flows:
        if len(flow) != 0:
            port_value = flow[0].data.data.sport
            if port_value == 80:
                port_value = flow[0].data.data.dport
            ports_to_compare.append(port_value)
    for existing_port in ports_to_compare:
        if existing_port == port:
            flows[ports_to_compare.index(existing_port)].append(eth)
            return
    flows[len(ports_to_compare)].append(eth)


# adds flow to list of streams if not there before
def identify_streams(ip, tcp):
    flow_index = [get_ip(ip.src), tcp.sport, get_ip(ip.dst), tcp.dport]
    # print(flow_index)
    if len(flow_ids) == 0:
        flow_ids.append(flow_index)
    else:
        unique_flow_flag = True
        for stream in flow_ids:
            if stream == flow_index:
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
        unsorted_packet.append(eth)
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

for packet in unsorted_packet:
    sort_flows(packet)
print(flows[0][4].data.data.seq)
print(flows[0][4].data.data.ack)

print(unsorted_packet.__len__())
print(len(flows[0]))
print(len(flows[1]))
print(len(flows[2]))

print(str(len(flows)) + " TCP flows initiated from sender")
for id in flow_ids:
    num = flow_ids.index(id)
    print(len(flows[num][len(flows[num]) - 1].data.data.data) + 32)  # length of TCP segment
    print("Source: " + flow_ids[num][0] + " at Port: " + str(flow_ids[num][1]) + " | Destination: " + flow_ids[num][2] + " at Port: " + str(flow_ids[num][3]))
    print("\tTransaction 1: Sequence Number = " + str(flows[num][4].data.data.seq))
    print("\t               Acknowledgement Number = " + str(flows[num][4].data.data.ack))
    print("\t               Receive Window Size = "+ str(flows[num][4].data.data.win * 16384))
    print("\tTransaction 2: Sequence Number = " + str(flows[num][5].data.data.seq))
    print("\t               Acknowledgement Number = " + str(flows[num][5].data.data.ack))
    print("\t               Receive Window Size = " + str(flows[num][5].data.data.win * 16384) + "\n")

f.close()
