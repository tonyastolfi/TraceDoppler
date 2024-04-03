import json
import sys


def correct_skew(rpc, avg_skew_usec):
    query_latency_usec = rpc["query.latency.usec"]
    reply_latency_usec = rpc["reply.latency.usec"]

    rpc["query.latency.usec"] = query_latency_usec - avg_skew_usec
    rpc["reply.latency.usec"] = reply_latency_usec + avg_skew_usec

    return rpc


def main(args):
    rpcs = json.load(sys.stdin)

    avg_skew_usec = (
        float(sum([rpc["split.skew.usec"] for rpc in rpcs])) /
        float(len(rpcs))
    )

    json.dump([correct_skew(rpc, avg_skew_usec) for rpc in rpcs], sys.stdout)
    pass


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
if __name__ == "__main__":
    main(sys.argv)
