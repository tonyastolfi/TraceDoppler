import json
import sys
import dpkt
from dpkt.utils import mac_to_str, inet_to_str


USEC_PER_SEC = 1000.0 * 1000.0


def read_pcaps(host, stream):
    raw_pcaps = dpkt.pcap.Reader(stream)
    pcaps = []

    for ts_sec, buf in raw_pcaps:
        eth = dpkt.ethernet.Ethernet(buf)
        if (isinstance(eth.data, dpkt.ip.IP) and
            isinstance(eth.data.data, dpkt.tcp.TCP)):
            ip = eth.data
            src_host = inet_to_str(ip.src)
            dst_host = inet_to_str(ip.dst)
        
            if host == src_host or host == dst_host:
                tcp = ip.data
                pcaps.append({
                    "time.usec": int(ts_sec * USEC_PER_SEC),
                    "size.bytes": len(buf),
                    "src.addr.ip": src_host,
                    "src.port.tcp": tcp.sport,
                    "dst.addr.ip": dst_host,
                    "dst.port.tcp": tcp.dport,
                    "seq.tcp": tcp.seq,
                })

    return pcaps
    

def read_pcap_file(host, filename):
    with open(filename, 'rb') as stream:
        return read_pcaps(host, stream)


def main(args):
    pcaps = read_pcaps(args[1], sys.stdin.buffer)
    json.dump(pcaps, sys.stdout)


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
if __name__ == "__main__":
    main(sys.argv)
