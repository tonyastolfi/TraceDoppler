from typing import List
import json
import argparse

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from pyskewadjuster import *

parser = argparse.ArgumentParser(description='JSON Trace Data to apply skew correction algorithm to')
parser.add_argument('file',type=str, action='store',help='Input file')

args = parser.parse_args()

data = None
with open(args.file, 'r') as f:
    data = json.load(f)['data']

services = discover_services(data)

def calculate_pairwise_skew_stats(tracedata, type='raw'):
    """Gets the latency distribution of a trace."""
    services = discover_services(tracedata)
    skew_corrections = {}
    pairwise_skew = {}
    pairwise_error = {}
    for service in services:
        skew_corrections[service] = {}
        pairwise_skew[service] = {}
        pairwise_error[service] = {}
        for service2 in services:
            pairwise_skew[service][service2] = []
            skew_corrections[service][service2] = []
            pairwise_error[service][service2] = []

    for trace in tracedata:
        call_tree = generate_call_tree(trace)
        span_lookup = {span['spanID']: span for span in trace['spans']}
        bfs_queue = list(call_tree.keys())
        while bfs_queue:
            parent = span_lookup[bfs_queue.pop(0)]
            parentService = parent['operationName']
            parent_correction = int(get_attribute_from_tags(parent, 'clock_skew_correction'))
            parent_skew = int(get_attribute_from_tags(parent, 'global_skew_ns'))

            children = parent['childSpanIds'] 
            for child in children:
                bfs_queue.append(child)
                child = span_lookup[child]
                childService = child['operationName']
    
                child_correction = int(get_attribute_from_tags(child, 'clock_skew_correction'))
                child_skew = int(get_attribute_from_tags(child, 'global_skew_ns'))

                pairwise_skew[parentService][childService].append(parent_skew - child_skew)
                skew_corrections[parentService][childService].append(parent_correction - child_correction)
                error = parent_skew - child_skew + (parent_correction - child_correction)
                pairwise_error[parentService][childService].append(error)

                # reflect
                pairwise_skew[childService][parentService].append(child_skew - parent_skew)
                skew_corrections[childService][parentService].append(child_correction - parent_correction)
                error = child_skew - parent_skew + (child_correction - parent_correction)
                pairwise_error[childService][parentService].append(error)

    for service in services:
        for service2 in services:
            pairwise_skew[service][service2] = np.array(pairwise_skew[service][service2])
            skew_corrections[service][service2] = np.array(skew_corrections[service][service2])
            pairwise_error[service][service2] = np.array(pairwise_error[service][service2])

    return skew_corrections, pairwise_skew, pairwise_error

def plot_latency_distribution(latency_distribution, fig=None, ax=None):
    """Plots the latency distribution of a trace."""
    if fig is None or ax is None:
        fig, ax = plt.subplots()
    for service, latencies in latency_distribution.items():
        for service2, latencies2 in latencies.items():
            if service == service2:
                continue
            latencies = latencies2
            latencies = np.array(latencies)/1e6
            ax.hist(latencies, bins=100, alpha=0.5, label=service)

def calculate_heatmap(pairwise_skew):
    """Plots the pairwise skew of a trace."""
    heatmap = np.zeros((len(pairwise_skew), len(pairwise_skew)))
    for idx1, (service, skews) in enumerate(pairwise_skew.items()):
        for idx2, (service2, skew) in enumerate(skews.items()):
            if service == service2:
                continue
            heatmap[idx1, idx2] = np.mean(skew)/1.0e6
    
    return heatmap
    
data = correct_skew(data)
skew_correction, pairwise_skew, pairwise_error = calculate_pairwise_skew_stats(data, type='raw')

fig, ax = plt.subplots(1, 2)
vmax = np.max([np.max(np.mean(list(pairwise_skew[service][service2]) + [1.0])) for service in services for service2 in services])/1.0e6
vmin = -vmax
cbar_ax = fig.add_axes([.895, .2, .03, .5])
_cmap = 'vlag'

heatmap = calculate_heatmap(pairwise_skew)
mask = ~np.tril(np.ones_like(heatmap, dtype=bool))
sns.heatmap(heatmap, annot=True, fmt=".2f", cmap=_cmap, cbar=True, cbar_ax=cbar_ax, ax=ax[0], vmax=vmax, vmin=vmin, mask=mask)
ax[0].set_xlabel('Latency (ms)')

heatmap = calculate_heatmap(pairwise_error)
sns.heatmap(heatmap, annot=True, fmt=".2f", cmap=_cmap, cbar=False, ax=ax[1], vmax=vmax, vmin=vmin, mask=mask)
ax[1].set_xlabel('Latency (ms)')

ax[0].set_aspect('equal', 'box')
ax[1].set_aspect('equal', 'box')

fig.suptitle('Pairwise Clock Skew Error Before and After Protocol (ms)')

ax[0].set_title('Before Protocol')
ax[1].set_title('After Protocol')

ax[0].set_xlabel('Node ID')
ax[0].set_ylabel('Node ID')
ax[1].set_xlabel('Node ID')
ax[1].set_ylabel('Node ID')
fig.tight_layout(rect=[0.05, 0, 0.9, 0.95])


fig.savefig('latency_hist_raw.png')