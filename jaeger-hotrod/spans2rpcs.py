import sys
import json


def update_latencies(rpc):
    query_send_time_usec = rpc["query.send.time.usec"]
    query_recv_time_usec = rpc["query.recv.time.usec"]
    reply_send_time_usec = rpc["reply.send.time.usec"]
    reply_recv_time_usec = rpc["reply.recv.time.usec"]

    query_latency_usec = query_recv_time_usec - query_send_time_usec
    reply_latency_usec = reply_recv_time_usec - reply_send_time_usec
    
    rpc["query.latency.usec"] = query_latency_usec
    rpc["reply.latency.usec"] = reply_latency_usec
    rpc["avg.latency.usec"] = (query_latency_usec + reply_latency_usec) / 2.0
    rpc["split.skew.usec"] = (query_latency_usec - reply_latency_usec) / 2.0
    
    return rpc


def main(args):
    # Read the spans from stdin as an array of JSON objects.
    #
    spans = json.load(sys.stdin)

    # Build a lookup table to quickly find any span by its ID.
    #
    spans_by_id = {
        span["spanID"]: span
        for span in spans
    }

    # Build a lookup table to find the parent ID of any span (by ID).
    #
    span_parent = {
        child: span["spanID"]
        for span in spans
        for child in span["children"]
    }

    # Sanity check: the mapped parent of every child of a span must be that span.
    #
    for span in spans:
        parent = span["spanID"]
        for child in span["children"]:
            assert span_parent[child] == parent

    # Join pairs of client and server spans to form a list of objects that contain
    # information about individual RPCs.
    #
    rpcs = [
        update_latencies({
            "link": ','.join((client_span["host"], server_span["host"])),
            "client.span": client_span["spanID"],
            "server.span": server_span["spanID"],
            "client.host": client_span["host"],
            "client.port": int(server_span["peer.port"] or 0),
            "server.host": server_span["host"],
            "server.port": int(client_span["peer.port"] or 0),
            "query.send.time.usec": client_span["startTime"], # t0
            "query.recv.time.usec": server_span["startTime"], # t1
            "reply.send.time.usec": server_span["endTime"], # t2
            "reply.recv.time.usec": client_span["endTime"], # t3
        })
        for server_span in spans
        if (server_span["kind"] == "server" and
            server_span["spanID"] in span_parent)
        for client_span in (spans_by_id[span_parent[server_span["spanID"]]],)
        if (client_span["kind"] == "client" and
            client_span["host"] != server_span["host"] and
            client_span["host"] == server_span["peer.host"] and
            server_span["host"] == client_span["peer.host"])
    ]


    # Write the results to stdout.
    #
    json.dump(rpcs, sys.stdout)


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
if __name__ == "__main__":
    main(sys.argv)
