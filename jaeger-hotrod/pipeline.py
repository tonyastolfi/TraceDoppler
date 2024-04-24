#=#=#==#==#===============+=+=+=+=++=++++++++++++++-++-+--+-+----+---------------
# Imports

import bisect
import collections
import dataclasses
import dpkt
import jq
import json
import math
import numpy
import random
import statistics
import sys

from dataclasses import dataclass
from dataclasses_json import dataclass_json
from dpkt.utils import mac_to_str, inet_to_str
from matplotlib import pyplot
from typing import Optional, Any


#=#=#==#==#===============+=+=+=+=++=++++++++++++++-++-+--+-+----+---------------
# Constants

USEC_PER_SEC = 1000.0 * 1000.0

TRACE_FILE = "data-2/traces-1711316915536.json"

PCAP_FILES = [
    ("192.168.1.195", "data-2/trace.epyc3451.2024-03-24T21-30-38.pcap"),
    ("192.168.1.187", "data-2/trace.thebeast.2024-03-24T17-30-40.pcap"),
]

HOST_TO_IP = {
    "thebeast": "192.168.1.187",
    "thebeast.en": "192.168.1.187",
    "epyc3451": "192.168.1.195",
    "epyc3451.en": "192.168.1.195",
}


#=#=#==#==#===============+=+=+=+=++=++++++++++++++-++-+--+-+----+---------------
# Data classes

#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
#
@dataclass_json
@dataclass(eq=True, frozen=True)
class Packet:
    size_bytes: int
    src_addr_ip: str
    dst_addr_ip: str
    src_port_tcp: int
    dst_port_tcp: int
    seq_tcp: int

    def from_pcap(buf):
        eth = dpkt.ethernet.Ethernet(buf)
        if not (isinstance(eth.data, dpkt.ip.IP) and
                isinstance(eth.data.data, dpkt.tcp.TCP)):
            return None

        ip = eth.data
        src_host = inet_to_str(ip.src)
        dst_host = inet_to_str(ip.dst)
        tcp = ip.data

        return Packet(size_bytes = len(buf),
                      src_addr_ip = src_host,
                      dst_addr_ip = dst_host,
                      src_port_tcp = tcp.sport,
                      dst_port_tcp = tcp.dport,
                      seq_tcp = tcp.seq)


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
#
@dataclass_json
@dataclass
class CapturedPacket:
    capture_host_ip: str
    capture_time_usec: float
    packet: Packet

    def from_pcap(capture_host_ip, ts_sec, buf):
        return CapturedPacket(capture_host_ip = capture_host_ip,
                              capture_time_usec = ts_sec * USEC_PER_SEC,
                              packet = Packet.from_pcap(buf))


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
#
@dataclass_json
@dataclass
class TracedPacket:
    send_time_usec: float
    recv_time_usec: float
    packet: Packet

    def ordinal(self):
        return (
            self.packet.src_addr_ip,
            self.packet.src_port_tcp,
            self.packet.dst_addr_ip,
            self.packet.dst_port_tcp,
            self.send_time_usec,
            self.recv_time_usec,
        )

    def find_closest(traced_packets, src_host, src_port, dst_host, dst_port,
                     time_usec):
        packets = traced_packets
        target = (src_host, src_port, dst_host, dst_port, time_usec, 0)
        init_i = bisect.bisect(packets, target, key=TracedPacket.ordinal)
        best_i = init_i
        best_dt = abs(packets[best_i].send_time_usec - time_usec)

        def probe(step, best_i, best_dt):
            i = init_i + step
            while (i >= 0 and i < len(packets) and
                   target[:4] == packets[i].ordinal()[:4] and
                   abs(packets[i].send_time_usec - time_usec) < best_dt):
                best_i = i
                best_dt = abs(packets[i].send_time_usec - time_usec)
                i += step

            return best_i, best_dt

        best_i, best_dt = probe(-1, best_i, best_dt)
        best_i, best_dt = probe(1, best_i, best_dt)

        return packets[best_i], best_dt


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
#
@dataclass_json
@dataclass
class PacketSpacing:
    """
    The time interval between the observation of a specific pair of packets,
    as recorded by both the sender and receiver.
    """
    send_interval_usec: Optional[float] = None
    recv_interval_usec: Optional[float] = None

    def delta(self):
        if (self.send_interval_usec is None or
            self.recv_interval_usec is None or
            self.send_interval_usec <= 0.0 or
            self.recv_interval_usec <= 0.0 or
            self.send_interval_usec >= USEC_PER_SEC or
            self.recv_interval_usec >= USEC_PER_SEC):
            return None

        return self.recv_interval_usec - self.send_interval_usec


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
#
@dataclass_json
@dataclass(eq=True, frozen=True)
class HostPair:
    """
    A directionally linked pair of hosts; a sender (src) and a receiver (dst).
    """
    src_addr_ip: str
    dst_addr_ip: str

    def from_packet(packet):
        return HostPair(src_addr_ip=packet.src_addr_ip,
                        dst_addr_ip=packet.dst_addr_ip)

    def reverse(self):
        return HostPair(src_addr_ip=self.dst_addr_ip,
                        dst_addr_ip=self.src_addr_ip)


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
#
@dataclass_json
@dataclass
class TransitDelta:
    """
    Statistical summary of the one-way overhead of packet transmission
    between a specific host pair, as obtained by the "two-packets"
    method (https://ieeexplore.ieee.org/document/1034915).
    """
    mean: float
    median: float
    stdev: float
    samples: list[float]

    def from_samples(packet_spacings, outlier_sigmas=3):
        if len(packet_spacings) == 0:
            return None

        samples = sorted([x.delta() for x in packet_spacings])
        samples = remove_outliers(samples, outlier_sigmas)

        return TransitDelta(mean=statistics.mean(samples),
                            median=statistics.median(samples),
                            stdev=statistics.stdev(samples),
                            samples=samples)


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
#
@dataclass_json
@dataclass
class TraceSpan:
    trace_id: str
    span_id: str
    start_time_usec: float
    end_time_usec: float
    children: list[str]
    host: str
    kind: str
    peer_host: str
    peer_port: int

    def from_raw_span(span):
        span_tags = tags_to_dict(span["tags"])
        process_tags = tags_to_dict(span["process"]["tags"])

        return TraceSpan(
            trace_id=span["traceID"],
            span_id=span["spanID"],
            start_time_usec=float(span["startTime"]),
            end_time_usec=float(span["startTime"]) + float(span["duration"]),
            children=span["childSpanIds"],
            host=normalize_host(process_tags.get("host.name")),
            kind=span_tags.get("span.kind"),
            peer_host=normalize_host(span_tags.get("net.peer.name") or
                                     span_tags.get("net.sock.peer.addr")),
            peer_port=int(span_tags.get("net.peer.port") or
                          span_tags.get("net.sock.peer.port") or
                          0)
        )


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
#
@dataclass_json
@dataclass
class LinkBias:
    query_bias: float
    reply_bias: float

    def from_transit_deltas(query_delta, reply_delta,
                            method=lambda delta: delta.mean):
        query_delta = method(query_delta)
        reply_delta = method(reply_delta)
        total_delta = query_delta + reply_delta

        query_bias = 2.0 * query_delta / total_delta
        reply_bias = 2.0 * reply_delta / total_delta

        assert math.isclose(query_bias + reply_bias, 2.0)

        return LinkBias(query_bias=query_bias,
                        reply_bias=reply_bias)

    def null():
        return LinkBias(1.0, 1.0)


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
#
@dataclass_json
@dataclass
class TraceRPC:
    link: HostPair
    client_span: str
    server_span: str
    client_host: str
    client_port: int
    server_host: str
    server_port: int
    query_send_time_usec: float
    query_recv_time_usec: float
    reply_send_time_usec: float
    reply_recv_time_usec: float

    # clock_skew = client_skew - server_skew = e
    # query_bias = Bq
    # reply_bias = Br
    # query_send_time = Sq
    # query_recv_time = Rq
    # reply_send_time = Sr
    # reply_recv_time = Rr
    # query_cost = Cq
    # reply_cost = Cr
    #
    #
    # By definition, Bq + Br = 2
    #
    # Rq = Sq - e + Cq * Bq
    # Rr = Sr + e + Cr * Br
    #
    # Cq = ((Rq - Sq) + e) / Bq
    # Cr = ((Rr - Sr) - e) / Br
    #
    # Assuming Cq = Cr,
    #
    # C = ((Rq - Sq) + e) / Bq
    # C = ((Rr - Sr) - e) / Br
    # ((Rq - Sq) + e) / Bq  = ((Rr - Sr) - e) / Br
    # ((Rq - Sq) + e) * Br  = ((Rr - Sr) - e) * Bq
    # ((Rq - Sq) * Br + e * Br  = ((Rr - Sr) * Bq - e * Bq
    # e * Br + e * Bq  = (Rr - Sr) * Bq -(Rq - Sq) * Br
    # e * (Br + Bq)  = (Rr - Sr) * Bq - (Rq - Sq) * Br
    # e * 2  = (Rr - Sr) * Bq - (Rq - Sq) * Br
    #
    # Therefore:
    # e = (((Rr - Sr) * Bq - ((Rq - Sq) * Br) / 2
    #

    def query_latency_usec(self):
        return self.query_recv_time_usec - self.query_send_time_usec

    def reply_latency_usec(self):
        return self.reply_recv_time_usec - self.reply_send_time_usec

    def query_cost(self, clock_skew, link_bias):
        return (self.query_latency_usec() + clock_skew) / link_bias.query_bias

    def reply_cost(self, clock_skew, link_bias):
        return (self.reply_latency_usec() - clock_skew) / link_bias.reply_bias

    def estimate_clock_skew(self, link_bias):
        return (self.reply_latency_usec() * link_bias.query_bias -
                self.query_latency_usec() * link_bias.reply_bias) / 2.0


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
#
@dataclass_json
@dataclass(eq=True, order=True, frozen=True)
class TCPPacketFlowId:
    """
    A four-tuple of (ip:port,ip:port) representing a TCP connection;
    normalized so that the first ip:port pair is less-than the second.
    """
    first_addr_ip: str
    first_port_tcp: int
    second_addr_ip: str
    second_port_tcp: int

    def from_endpoints(first_addr_ip, first_port_tcp, second_addr_ip, second_port_tcp):
        if (first_addr_ip, first_port_tcp) > (second_addr_ip, second_port_tcp):
            first_addr_ip, second_addr_ip = second_addr_ip, first_addr_ip
            first_port_tcp, second_port_tcp = second_port_tcp, first_port_tcp

        return TCPPacketFlowId(first_addr_ip=first_addr_ip,
                               first_port_tcp=first_port_tcp,
                               second_addr_ip=second_addr_ip,
                               second_port_tcp=second_port_tcp)

    def from_packet(packet):
        return TCPPacketFlowId.from_endpoints(
            packet.src_addr_ip, packet.src_port_tcp,
            packet.dst_addr_ip, packet.dst_port_tcp
        )

    def from_rpc(rpc):
        return TCPPacketFlowId.from_endpoints(
            rpc.client_host, rpc.client_port,
            rpc.server_host, rpc.server_port
        )


#=#=#==#==#===============+=+=+=+=++=++++++++++++++-++-+--+-+----+---------------
# Functions

def tags_to_dict(tags):
    """
    Converts a list of dicts with "key" and "value" keys into a single dict.
    """
    return {t["key"]: t["value"] for t in tags}


def normalize_host(host):
    """
    Returns the value in HOST_TO_IP for the passed host string, if present, else
    returns host.
    """
    return HOST_TO_IP.get(host) or host


def remove_outliers(samples, n_sigmas=3):
    sigma = statistics.stdev(samples)
    median = statistics.median(samples)
    return [x for x in samples
            if abs(x - median) < sigma * n_sigmas]


def read_spans(stream):
    raw_trace = json.load(stream)
    raw_spans = [span
                 for trace in raw_trace["data"]
                 for span in trace["spans"]]

    return [TraceSpan.from_raw_span(s) for s in raw_spans]


def read_spans_from_trace_file(filename):
    with open(TRACE_FILE, 'r') as stream:
        return read_spans(stream)


def rpcs_from_trace_spans(spans):
    # Build a lookup table to quickly find any span by its ID.
    #
    spans_by_id = {
        span.span_id: span
        for span in spans
    }

    # Build a lookup table to find the parent ID of any span (by ID).
    #
    span_parent = {
        child: span.span_id
        for span in spans
        for child in span.children
    }

    # Sanity check: the mapped parent of every child of a span must be that span.
    #
    for span in spans:
        parent = span.span_id
        for child in span.children:
            assert span_parent[child] == parent

    # Join pairs of client and server spans to form a list of objects that contain
    # information about individual RPCs.
    #
    rpcs = [
        TraceRPC(
            link=HostPair(src_addr_ip=client_span.host,
                          dst_addr_ip=server_span.host),
            client_span=client_span.span_id,
            server_span=server_span.span_id,
            client_host=client_span.host,
            client_port=int(server_span.peer_port or 0),
            server_host=server_span.host,
            server_port=int(client_span.peer_port or 0),
            query_send_time_usec=client_span.start_time_usec,
            query_recv_time_usec=server_span.start_time_usec,
            reply_send_time_usec=server_span.end_time_usec,
            reply_recv_time_usec=client_span.end_time_usec
        )
        for server_span in spans
        if (server_span.kind == "server" and server_span.span_id in span_parent)
        for client_span in (spans_by_id[span_parent[server_span.span_id]],)
        if (client_span.kind == "client" and
            client_span.host != server_span.host and
            client_span.host == server_span.peer_host and
            server_span.host == client_span.peer_host)
    ]

    return rpcs


def read_pcaps(host, stream):
    raw_pcaps = dpkt.pcap.Reader(stream)
    return [
        captured
        for ts_sec, buf in raw_pcaps
        for captured in (CapturedPacket.from_pcap(host, ts_sec, buf),)
        if (captured.packet is not None and
            (host == captured.packet.src_addr_ip or
             host == captured.packet.dst_addr_ip))
    ]


def read_pcap_file(host, filename):
    with open(filename, 'rb') as stream:
        return read_pcaps(host, stream)


def link_bias_from_captured_packets(captured_packets, outlier_sigmas=3):
    # (first_packet, second_packet) -> PacketSpacing
    #
    packet_spacing = collections.defaultdict(lambda: PacketSpacing())

    # capture_host -> (packet -> capture_time_usec)
    #
    capture_time_by_host_packet = collections.defaultdict(lambda: collections.defaultdict(lambda: 0.0))

    # HostPair -> Packet
    #
    prev_by_pair = collections.defaultdict(lambda: None)

    # First pass: Populate packet_spacing (send only) and capture_time_by_packet.
    #
    for captured in captured_packets:
        assert captured is not None

        host_pair = HostPair.from_packet(captured.packet)

        capture_time_by_host_packet[captured.capture_host_ip][captured.packet] = captured.capture_time_usec

        # If this packet was captured by the sending host, add an entry to the packet spacing map.
        #
        is_sender = (captured.capture_host_ip == captured.packet.src_addr_ip)
        if is_sender:
            prev = prev_by_pair[host_pair]

            if prev is not None:
                delta = captured.capture_time_usec - prev.capture_time_usec

                # Ignore non-positive packet send intervals.
                #
                if delta > 0.0:
                    packet_spacing[(prev.packet, captured.packet)].send_interval_usec = delta

            prev_by_pair[host_pair] = captured

    # Second pass: Fill in missing recv_interval_usec fields in packet_spacing values.
    #
    for (first_packet, second_packet) in packet_spacing:
        assert first_packet.src_addr_ip == second_packet.src_addr_ip
        assert first_packet.dst_addr_ip == second_packet.dst_addr_ip

        dst_host = first_packet.dst_addr_ip

        first_packet_recv_time_usec = capture_time_by_host_packet[dst_host][first_packet]
        if first_packet_recv_time_usec == 0.0:
            continue

        second_packet_recv_time_usec = capture_time_by_host_packet[dst_host][second_packet]
        if second_packet_recv_time_usec == 0.0:
            continue

        delta = second_packet_recv_time_usec - first_packet_recv_time_usec

        if delta > 0.0:
            packet_spacing[(first_packet, second_packet)].recv_interval_usec = delta

    # Filter out any invalid (==None) PacketSpacing delta values.
    #
    packet_spacing = {
        packet_pair: spacing
        for packet_pair, spacing in packet_spacing.items()
        if spacing.delta() is not None
    }

    # Compute the final result.
    #
    packet_spacing_by_pair = collections.defaultdict(lambda: [])
    for (packet, _), spacing in packet_spacing.items():
        packet_spacing_by_pair[
            HostPair(src_addr_ip = packet.src_addr_ip,
                     dst_addr_ip = packet.dst_addr_ip)
        ].append(spacing)

    transit_deltas_by_host_pair = {
        host_pair: transit_delta
        for host_pair, samples in packet_spacing_by_pair.items()
        for transit_delta in (TransitDelta.from_samples(samples, outlier_sigmas),)
        if transit_delta is not None
    }

    link_bias = {}

    for host_pair, transit_delta in transit_deltas_by_host_pair.items():
        reverse_pair = host_pair.reverse()
        if reverse_pair not in transit_deltas_by_host_pair:
            continue

        print(transit_delta)

        reverse_delta = transit_deltas_by_host_pair[reverse_pair]

        link_bias[host_pair] = LinkBias.from_transit_deltas(
            query_delta=transit_delta,
            reply_delta=reverse_delta
        )

    return link_bias


def captured_to_traced_packets(all_captured):
    # The final result.
    #
    traced_packets = []

    # Use a dict to match up packets captured on the sender and receiver.
    #
    match_by_packet = {}

    for captured in all_captured:

        # If we haven't seen this packet before, add it and move on.
        #
        if captured.packet not in match_by_packet:
            match_by_packet[captured.packet] = captured
            continue

        # This packet has already been seen.  Verify we have both sender
        # and receiver CapturedPacket and create a single TracedPacket
        # with the timestamps of both.
        #
        matched = match_by_packet[captured.packet]

        if matched.capture_host_ip == captured.packet.src_addr_ip:
            sent, received = matched, captured
        else:
            assert matched.capture_host_ip == captured.packet.dst_addr_ip
            sent, received = captured, matched

        traced_packets.append(
            TracedPacket(send_time_usec=sent.capture_time_usec,
                         recv_time_usec=received.capture_time_usec,
                         packet=sent.packet))

        del(match_by_packet[captured.packet])

    return sorted(traced_packets, key=TracedPacket.ordinal)


def replace_packet_timestamps(rpcs, traced_packets):
    result = []

    for rpc in rpcs:
        query_packet, _dt = TracedPacket.find_closest(
            traced_packets,
            rpc.client_host, rpc.client_port,
            rpc.server_host, rpc.server_port,
            rpc.query_send_time_usec
        )
        reply_packet, _dt = TracedPacket.find_closest(
            traced_packets,
            rpc.server_host, rpc.server_port,
            rpc.client_host, rpc.client_port,
            rpc.reply_send_time_usec
        )
        result.append(dataclasses.replace(
            rpc,
            query_send_time_usec=query_packet.send_time_usec,
            query_recv_time_usec=query_packet.recv_time_usec,
            reply_send_time_usec=reply_packet.send_time_usec,
            reply_recv_time_usec=reply_packet.recv_time_usec
        ))

    return result


def pretty_json(dataclass_value):
    return json.dumps(dataclass_value.to_dict(), indent=2)


def show_histogram(data, xlabel="Value", ylabel="Count"):
    min_value = min(data)
    max_value = max(data)

    min_value -= min_value % 10
    max_value += 9
    max_value -= max_value % 10

    bins = numpy.linspace(min_value, max_value, 100)
    fig, ax = pyplot.subplots()

    ax.hist(data, bins, alpha=0.5, label=None)
    #ax.legend(loc='upper right')
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)


#=#=#==#==#===============+=+=+=+=++=++++++++++++++-++-+--+-+----+---------------

def main(args):
    # Load all captured packets.
    #
    all_captured = [
        p
        for host, filename in PCAP_FILES
        for p in read_pcap_file(host, filename)
    ]

    # Calculate transit deltas using the "Two Packets Method."
    #
    link_bias = link_bias_from_captured_packets(all_captured)
    print("len(link_bias)=", len(link_bias))

    for host_pair, bias in link_bias.items():
        print(host_pair, bias)

    # Trace captured packets from sender to receiver.
    #
    traced_packets = captured_to_traced_packets(all_captured)
    for p in traced_packets[:3]:
        print(pretty_json(p))

    # Load spans.
    #
    spans = read_spans_from_trace_file(TRACE_FILE)
    for s in spans[:5]:
        print(pretty_json(s))

    # Convert spans to RPCs.
    #
    rpcs = rpcs_from_trace_spans(spans)

    # Extract RPC flow ids and filter packets.
    #
    rpc_flow_ids = set(TCPPacketFlowId.from_rpc(r) for r in rpcs)
    rpc_packets = [p for p in all_captured
                   if TCPPacketFlowId.from_packet(p.packet) in rpc_flow_ids]

    print(f"\nlen(all_captured)={len(all_captured)}, len(rpc_packets)={len(rpc_packets)}")
    filtered_link_bias = link_bias_from_captured_packets(rpc_packets)
    print("len(filtered_link_bias)=", len(filtered_link_bias))
    for host_pair, bias in filtered_link_bias.items():
        print(host_pair, bias)

    # Print some RPCs and derived information.
    #
    def print_rpc_summary(r):
        bias = link_bias[r.link]
        clock_skew = r.estimate_clock_skew(bias)

        print("\nRPC:")
        print(pretty_json(r))
        print(f"query_latency={r.query_latency_usec()}us")
        print(f"reply_latency={r.reply_latency_usec()}us")
        print(f"clock_skew={clock_skew}")
        print(f"query_cost={r.query_cost(clock_skew, bias)}, reply_cost={r.reply_cost(clock_skew, bias)}")

    print("\nRaw RPCS:")
    for r in rpcs[:5]:
        print_rpc_summary(r)

    packet_ts_rpcs = replace_packet_timestamps(rpcs, traced_packets)
    print("\nPacket Timestamp-Corrected RPCS:")
    for r in packet_ts_rpcs[:5]:
        print_rpc_summary(r)

    skew_no_bias = remove_outliers(
        [r.estimate_clock_skew(LinkBias.null())
         for r in rpcs]
    )

    #skew_all_packets_bias = [r.estimate_clock_skew(link_bias[r.link])
    #                         for r in rpcs]

    skew_rpc_packets_bias = remove_outliers(
        [r.estimate_clock_skew(filtered_link_bias[r.link])
         for r in rpcs]
    )

    skew_no_bias_pts = remove_outliers(
        [r.estimate_clock_skew(LinkBias.null())
         for r in packet_ts_rpcs]
    )

    #skew_all_packets_bias = [r.estimate_clock_skew(link_bias[r.link])
    #                         for r in packet_ts_rpcs]

    skew_rpc_packets_bias_pts = remove_outliers(
        [r.estimate_clock_skew(filtered_link_bias[r.link])
         for r in packet_ts_rpcs]
    )

    data = skew_no_bias + skew_no_bias_pts + skew_rpc_packets_bias_pts

    min_value = min(data)
    max_value = max(data)

    min_value -= min_value % 10
    max_value += 9
    max_value -= max_value % 10

    bins = numpy.linspace(min_value, max_value, 100)

    fig, ax = pyplot.subplots()

    def add_to_hist(data, label):
        ax.hist(data, bins, alpha=0.5,
                label=f"{label} (avg={round(statistics.mean(data), 1)} σ={round(statistics.stdev(data), 2)})")

    add_to_hist(skew_no_bias, "Raw")
    add_to_hist(skew_no_bias_pts, "PTS")
    add_to_hist(skew_rpc_packets_bias, "2PM")
    add_to_hist(skew_rpc_packets_bias_pts, "PTS, 2PM")

    ax.legend(loc='upper left')
    ax.set_xlabel("Clock Skew (client - server), usec")
    ax.set_ylabel("Count")

    pyplot.show()



#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
if __name__ == "__main__":
    main(sys.argv)
