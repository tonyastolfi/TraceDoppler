import json
import numpy
import random
import sys

from matplotlib import pyplot


def main(args):
    rpcs = json.load(sys.stdin)

    skews_usec = [
        rpc["split.skew.usec"]
        for rpc in rpcs
    ]

    min_skew_usec = min(skews_usec)
    max_skew_usec = max(skews_usec)

    min_skew_usec -= min_skew_usec % 10
    max_skew_usec += 9
    max_skew_usec -= max_skew_usec % 10

    print("min=", min_skew_usec)
    print("max=", max_skew_usec)

    bins = numpy.linspace(min_skew_usec, max_skew_usec, 100)

    fig, ax = pyplot.subplots()

    ax.hist(skews_usec, bins, alpha=0.5, label=None)
    #ax.legend(loc='upper right')
    ax.set_xlabel('Server-side Clock Skew (usec)')
    ax.set_ylabel('Count')

    if len(args) >= 2:
        output_image_filename = args[1]
        fig.savefig(output_image_filename)
        pyplot.close(fig)
    else:
        pyplot.show()


#==#==========+==+=+=++=+++++++++++-+-+--+----- --- -- -  -  -   -
if __name__ == "__main__":
    main(sys.argv)
