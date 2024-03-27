import json
import numpy
import random
import sys

from matplotlib import pyplot


rpcs = json.load(sys.stdin)

all_latencies = [
    latency_usec
    for rpc in rpcs
    for latency_usec in (rpc["query.latency.usec"],
                         rpc["reply.latency.usec"])
]

min_latency_usec = min(all_latencies)
max_latency_usec = max(all_latencies)

min_latency_usec -= min_latency_usec % 10
max_latency_usec += 9
max_latency_usec -= max_latency_usec % 10

print("min=", min_latency_usec)
print("max=", max_latency_usec)

query_latency_usec = [rpc["query.latency.usec"] for rpc in rpcs]
reply_latency_usec = [rpc["reply.latency.usec"] for rpc in rpcs]

bins = numpy.linspace(min_latency_usec, max_latency_usec, 100)

fig, ax = pyplot.subplots()

ax.hist(query_latency_usec, bins, alpha=0.5, label='query')
ax.hist(reply_latency_usec, bins, alpha=0.5, label='reply')
ax.legend(loc='upper right')
ax.set_xlabel('Network Delay (usec)')
ax.set_ylabel('Count')
pyplot.show()

