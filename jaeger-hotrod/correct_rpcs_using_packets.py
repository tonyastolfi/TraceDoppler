import bisect
import json
import sys



PACKET_SRC_IP = 0
PACKET_SRC_PORT = 1
PACKET_DST_IP = 2
PACKET_DST_PORT = 3
PACKET_SEND_TIME = 4
PACKET_RECV_TIME = 5
PACKET_SEQ = 6


def find_packet(packets, src_host, src_port, dst_host, dst_port, time_usec):
    key = (src_host, src_port, dst_host, dst_port, time_usec, 0, 0)
    init_i = bisect.bisect(packets, key)
    best_i = init_i
    best_dt = abs(packets[best_i][PACKET_SEND_TIME] - time_usec)

    def probe(step, best_i, best_dt):
        i = init_i + step
        while (i >= 0 and i < len(packets) and 
               key[0:4] == packets[i][0:4] and
               abs(packets[i][PACKET_SEND_TIME] - time_usec) < best_dt):
            best_i = i
            best_dt = abs(packets[i][PACKET_SEND_TIME] - time_usec)
            i += step

        return best_i, best_dt
    
    best_i, best_dt = probe(-1, best_i, best_dt)
    best_i, best_dt = probe(1, best_i, best_dt)

    print("best_i=", best_i)
    print("packet=", packets[best_i])
    print("   key=", key)
    
    return packets[best_i], best_dt


def main(args):
    packets = None
    packets_json_file = args[1]

    print("file is ", packets_json_file)
    with open(packets_json_file, 'r') as fp:
        packets = [tuple(pkt) for pkt in json.load(fp)]

    rpcs = json.load(sys.stdin)

    print("len(packets)=", len(packets))
    
    for rpc in rpcs:
        client_host = rpc["client.host"]
        client_port = rpc["client.port"]
        server_host = rpc["server.host"]
        server_port = rpc["server.port"]
        query_send_time_usec = rpc["query.send.time.usec"] 
        query_recv_time_usec = rpc["query.recv.time.usec"] 
        reply_send_time_usec = rpc["reply.send.time.usec"] 
        reply_recv_time_usec = rpc["reply.recv.time.usec"] 

        query_pkt, query_dt = find_packet(packets, client_host, client_port,
                                          server_host, server_port, query_send_time_usec)
        
        reply_pkt, reply_dt = find_packet(packets, server_host, server_port,
                                          client_host, client_port, reply_send_time_usec)
        
        old_latency = query_recv_time_usec - query_send_time_usec
        new_latency = query_pkt[PACKET_RECV_TIME] - query_pkt[PACKET_SEND_TIME]

        print("QUERY: ", query_send_time_usec, "->", query_pkt[PACKET_SEND_TIME],
              " (", query_dt, ")  ",
              query_recv_time_usec, "->", query_pkt[PACKET_RECV_TIME], "  ",
              old_latency, "->", new_latency, "  (", new_latency - old_latency, ")")

        old_latency = reply_recv_time_usec - reply_send_time_usec
        new_latency = reply_pkt[PACKET_RECV_TIME] - reply_pkt[PACKET_SEND_TIME]
                    
        print("REPLY: ", reply_send_time_usec, "->", reply_pkt[PACKET_SEND_TIME],
              " (", reply_dt, ")  ",
              reply_recv_time_usec, "->", reply_pkt[PACKET_RECV_TIME], "  ",
              old_latency, "->", new_latency, "  (", new_latency - old_latency, ")")

        print()

    print("len(packets)=", len(packets))
        


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
if __name__ == "__main__":
    main(sys.argv)
