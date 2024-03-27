import json
import sys


#=#=#==#==#===============+=+=+=+=++=++++++++++++++-++-+--+-+----+---------------

def tags_to_dict(tags):
    """
    Converts a list of dicts with "key" and "value" keys into a single dict.
    """
    return {t["key"]: t["value"] for t in tags}


HOST_TO_IP = {
    "thebeast": "192.168.1.187",
    "thebeast.en": "192.168.1.187",
    "epyc3451": "192.168.1.195",
    "epyc3451.en": "192.168.1.195",
}

def normalize_host(host):
    """
    Returns the value in HOST_TO_IP for the passed host string, if present, else
    returns host.
    """
    return HOST_TO_IP.get(host) or host


#=#=#==#==#===============+=+=+=+=++=++++++++++++++-++-+--+-+----+---------------

# Read the trace data from stdin as JSON data.
#
raw_trace = json.load(sys.stdin)

# Flatten out the nested structure to produce a list of span objects.
#
raw_spans = [
    span
    for trace in raw_trace["data"]
    for span in trace["spans"]
]

# Restructure each span object, discarding information we don't think we will
# use.
#
spans = [
    {
        "traceID": span["traceID"],
        "spanID": span["spanID"],
        "startTime": span["startTime"],
        "endTime": span["startTime"] + span["duration"],
        "tags": span_tags,
        "children": span["childSpanIds"],
        "host": normalize_host(process_tags.get("host.name")),
        "kind": span_tags.get("span.kind"),
        "peer.host": normalize_host(span_tags.get("net.peer.name") or
                                     span_tags.get("net.sock.peer.addr")),
        "peer.port": (span_tags.get("net.peer.port") or
                      span_tags.get("net.sock.peer.port")),
    }
    for span in raw_spans
    for span_tags in (tags_to_dict(span["tags"]),)
    for process_tags in (tags_to_dict(span["process"]["tags"]),)
]

# Write the output to stdout.
#
json.dump(spans, sys.stdout)
