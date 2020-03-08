import dpkt


# returns the source/destination IP address
def get_ip(ip_in_hex):
    new_ip = ''
    for num in ip_in_hex:
        new_ip = new_ip + str(num) + "."

    new_ip = new_ip[0:new_ip.__len__() - 1]
    return new_ip


def analysis_pcap_tcp():
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

    print(eth)
    print(ip.src)
    print(tcp)


file_name = 'assignment2.pcap'  # sys.argv[1]
f = open(file_name, 'rb')
pcap = dpkt.pcap.Reader(f)

f.close()
