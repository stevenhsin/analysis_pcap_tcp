import dpkt

f = open('assignment2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data

print(eth)
print(ip.src)
print(tcp)


# returns the source IP address
def get_src_ip(src_in_hex):
    src_ip = ''
    for num in src_in_hex:
        src_ip = src_ip + str(num) + "."

    src_ip = src_ip[0:src_ip.__len__() - 1]
    return(src_ip)


f.close()
