import json
import sys
import dpkt
import pcap2json
from dpkt.utils import mac_to_str, inet_to_str


def main(args):
    host_pcap_files = {
        host: pcap_file
        for arg in args[1:]
        for host, pcap_file in (tuple(arg.split('=')),)
    }
    #print(host_pcap_map)
    #print(json.dumps(host_pcap_files))

    host_pcaps = {
        host: pcap2json.read_pcap_file(host, filename)
        for host, filename in host_pcap_files.items()
    }

    # (src.ip, src.port, dst.ip, dst.port, seq) -> {"sendTime":, "recvTime":}
    #
    all_packets = {}
    for host, packets in host_pcaps.items():
        for pkt in packets:
            src_host = pkt["src.ip"]
            dst_host = pkt["dst.ip"]

            if host == src_host or host == dst_host:
                key = (src_host, pkt["src.port"], dst_host, pkt["dst.port"], pkt["seq"])

                if key not in all_packets:
                    all_packets[key] = {}

                if host == src_host:
                    all_packets[key]["send.time.usec"] = pkt["time.usec"]
                else:
                    all_packets[key]["recv.time.usec"] = pkt["time.usec"]

    packets_with_ts = sorted([
        (src_ip, src_port,
         dst_ip, dst_port,
         times['send.time.usec'],
         times['recv.time.usec'],
         seq)
        for ((src_ip, src_port, dst_ip, dst_port, seq), times) in all_packets.items()
        if "send.time.usec" in times and "recv.time.usec" in times
    ])
    
    json.dump(packets_with_ts, sys.stdout)


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
if __name__ == "__main__":
    main(sys.argv)
