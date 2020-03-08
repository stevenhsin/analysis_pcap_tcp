import dpkt

f = open('assignment2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    print(ts, len(buf))
