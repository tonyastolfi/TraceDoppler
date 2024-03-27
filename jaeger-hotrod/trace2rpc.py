import json
import collections
import csv
import dpkt
import bisect
from dpkt.utils import mac_to_str, inet_to_str


raw_trace = None

with open('traces-1711316915536.json', 'rb') as fp:
    raw_trace = json.load(fp)

#print(raw_trace)

raw_spans = [span
             for trace in raw_trace["data"]
             for span in trace["spans"]]          


def tags_to_dict(tags):
    return {t["key"]: t["value"] for t in tags}
        

#print(json.dumps(raw_spans))

host_to_ip = {
    "thebeast": "192.168.1.187",
    "thebeast.en": "192.168.1.187",
    "epyc3451": "192.168.1.195",
    "epyc3451.en": "192.168.1.195",
}

def normalize_host(host):
    return host_to_ip.get(host) or host


raw_packets = []

pcap_epyc3451 = 'trace.epyc3451.2024-03-24T21-30-38.pcap'
pcap_thebeast = 'trace.thebeast.2024-03-24T17-30-40.pcap'

def read_pcap(filename):
    packets = {
        "by_seq": [],
        "by_ts": [],
    }
    
    with open(filename, 'rb') as fp:
        pcap = dpkt.pcap.Reader(fp)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP):
                ip = eth.data
                tcp = ip.data
                #print(f'{ts}, {inet_to_str(ip.src)}:{tcp.sport} -> {inet_to_str(ip.dst)}:{tcp.dport}: {tcp.seq}')

                flow_seq = (inet_to_str(ip.src), tcp.sport,
                            inet_to_str(ip.dst), tcp.dport,
                            tcp.seq)
                
                packets["by_seq"].append((flow_seq, ts))
                packets["by_ts"].append((ts, flow_seq))

    return packets

    

host_packets = {}
host_packets["192.168.1.195"] = read_pcap(pcap_epyc3451)
host_packets["192.168.1.187"] = read_pcap(pcap_thebeast)

print(json.dumps(host_packets))

def find_packets_for_rpc(rpc, host_packets):
    




spans = {
    span["spanID"]: {
        "traceID": span["traceID"],
        "spanID": span["spanID"],
        "start": span["startTime"],
        "end": span["startTime"] + span["duration"],
        "tags": span_tags,
        "children": span["childSpanIds"],
        "host": normalize_host(process_tags.get("host.name")),
        "kind": span_tags.get("span.kind"),
        "net.peer.host": normalize_host(span_tags.get("net.peer.name") or span_tags.get("net.sock.peer.addr")),
        "net.peer.port": span_tags.get("net.peer.port") or span_tags.get("net.sock.peer.port"),
    }
    for span in raw_spans
    for span_tags in (tags_to_dict(span["tags"]),)
    for process_tags in (tags_to_dict(span["process"]["tags"]),)
}

#print(json.dumps(spans))


#print(json.dumps([s for s in spans.values() if s['kind'] == 'server']))

span_parent = {
    child: span["spanID"]
    for span in spans.values()
    for child in span["children"]
}

# Sanity check.
#
for span in spans.values():
    parent = span["spanID"]
    for child in span["children"]:
        assert span_parent[child] == parent
        

#print(json.dumps(span_parent))

rpcs = [
    {
        "edge": ':'.join((parent_span["host"], child_span["host"])),
        "client.span": parent_span["spanID"],
        "server.span": child_span["spanID"],        
        "client.host": parent_span["host"],
        "client.port": int(child_span["net.peer.port"] or 0),
        "server.host": child_span["host"],
        "server.port": int(parent_span["net.peer.port"] or 0),
        "request.latency": child_span["start"] - parent_span["start"],
        "response.latency": parent_span["end"] - child_span["end"],
        "avg.latency": (
            (child_span["start"] - parent_span["start"]) +
            (parent_span["end"] - child_span["end"])
        ) / 2.0,
        "avg.skew": (
            (child_span["start"] + child_span["end"]) -
            (parent_span["start"] + parent_span["end"])            
        ) / 2.0,
        "request.send.time": parent_span["start"], # t0
        "request.recv.time": child_span["start"], # t1
        "response.send.time": child_span["end"], # t3
        "response.recv.time": parent_span["end"], # t2
    }
    for child_span in spans.values() if child_span["kind"] == "server" and child_span["spanID"] in span_parent
    for parent_span in (spans[span_parent[child_span["spanID"]]],)
    if (parent_span["host"] != child_span["host"] and
        parent_span["host"] == child_span["net.peer.host"] and
        child_span["host"] == parent_span["net.peer.host"])
]

#print(json.dumps(list(spans.values())[0]))

hist = {}
for rpc in rpcs:
    edge = rpc["edge"]
    
    if edge not in hist:
        hist[edge] = {
            "count": 0,
            "total.latency": 0.0,
            "total.avg.skew": 0.0,
            "avg.latencies": [],
            "request.latencies": [],
            "response.latencies": [],
            "dist": {},
        }
        
    latency = rpc["avg.latency"]
    request_latency = rpc["request.latency"]
    response_latency = rpc["response.latency"]
    avg_skew = rpc["avg.skew"]
    bucket = int(latency / 10) * 10
        
    hist[edge]["count"] += 1
    hist[edge]["total.latency"] += latency
    hist[edge]["total.avg.skew"] += avg_skew
    hist[edge]["avg.latencies"] += [latency]
    hist[edge]["request.latencies"] += [request_latency]
    hist[edge]["response.latencies"] += [response_latency]

    if bucket not in hist[edge]["dist"]:
        hist[edge]["dist"][bucket] = 1
    else:
        hist[edge]["dist"][bucket] += 1

    #+++++++++++-+-+--+----- --- -- -  -  -   -


for edge in hist:
    hist[edge]["avg.latencies"] = sorted(hist[edge]["avg.latencies"])
    hist[edge]["request.latencies"] = sorted(hist[edge]["request.latencies"])
    hist[edge]["response.latencies"] = sorted(hist[edge]["response.latencies"])
    hist[edge]["dist"] = collections.OrderedDict(sorted(hist[edge]["dist"].items()))
    hist[edge]["avg.latency"] = hist[edge]["total.latency"] / hist[edge]["count"]
    hist[edge]["avg.skew"] = hist[edge]["total.avg.skew"] / hist[edge]["count"]


for rpc in rpcs:
    edge = rpc["edge"]
    avg_skew = hist[edge]["avg.skew"]
    rpc["corrected.request.latency"] = rpc["request.latency"] - avg_skew
    rpc["corrected.response.latency"] = rpc["response.latency"] + avg_skew
    

with open('rpcs.json', 'w') as fp:
    json.dump(rpcs, fp)

with open('hist.json', 'w') as fp:
    json.dump(hist, fp)

with open('rpcs.csv', 'w') as fp:
    wr = csv.writer(fp, delimiter=',')
    wr.writerow(rpcs[0].keys())
    for r in rpcs:
        wr.writerow(r.values())

    
