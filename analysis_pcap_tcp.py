import dpkt


# adds stream to list of streams if not there before
def identify_streams(ip, tcp):
    stream_index = [get_ip(ip.src), tcp.sport, get_ip(ip.dst), tcp.dport]
    print(stream_index)
    if len(streams) == 0:
        streams.append(stream_index)
    else:
        unique_stream_flag = True
        for stream in streams:
            if stream == stream_index:
                unique_stream_flag = False
        if unique_stream_flag:
            streams.append(stream_index)
    filter_streams()


# communication from Host A on Port a to Host B on Port b is the same stream as Host B on Port b to Host A on Port a
def filter_streams():
    for stream in streams:
        reverse_order = [stream[2], stream[3], stream[0], stream[1]]
        for s in streams:
            if reverse_order == s:
                streams.remove(s)


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
        ip = eth.data
        tcp = ip.data
        if check_flows(tcp):
            global tcp_flows
            tcp_flows = tcp_flows + 1
        identify_streams(ip, tcp)
    # print(eth)
    # print(ip.src)
    # print(tcp.sport)
    print(tcp)


tcp_flows = 0
streams = []
file_name = 'assignment2.pcap'  # sys.argv[1]
f = open(file_name, 'rb')
pcap = dpkt.pcap.Reader(f)
analyze_pcap_tcp()
print(tcp_flows)
print(len(streams))
print(streams)
f.close()
