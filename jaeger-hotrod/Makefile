
OUTPUT_FILES += output/data-1/traces-1711294619583_spans.json
OUTPUT_FILES += output/data-1/traces-1711294619583_rpcs.json

OUTPUT_FILES += output/data-2/traces-1711316915536_spans.json
OUTPUT_FILES += output/data-2/traces-1711316915536_rpcs.json
OUTPUT_FILES += output/data-2/traces-1711316915536_packets.json
OUTPUT_FILES += output/data-2/traces-1711316915536_rpcs_packet_ts.json
OUTPUT_FILES += output/data-2/traces-1711316915536_rpc_latency_dist.png
OUTPUT_FILES += output/data-2/traces-1711316915536_rpc_latency_dist_with_skew_correct.png
OUTPUT_FILES += output/data-2/traces-1711316915536_rpc_latency_dist_with_packet_correct.png
OUTPUT_FILES += output/data-2/traces-1711316915536_rpc_latency_dist_with_packet_and_skew_correct.png
OUTPUT_FILES += output/data-2/traces-1711316915536_rpc_skew_dist.png
OUTPUT_FILES += output/data-2/traces-1711316915536_rpc_skew_dist_with_packet_correct.png

.PHONY: all
all: $(OUTPUT_FILES)

.PHONY: venv
venv: env/

env/:
	python3 -m venv env
	source env/bin/activate && pip install --upgrade pip
	source env/bin/activate && pip install dpkt matplotlib numpy dataclasses-json jq

output/:
	mkdir -p output


.PHONY: clean
clean:
	rm -rf output/
	rm -rf env/

output/%_spans.json: %.json env/
	mkdir -p "$(shell dirname "$@")"
	source env/bin/activate && python traces2spans.py < $< > $@

output/%_rpcs.json: output/%_spans.json env/
	mkdir -p "$(shell dirname "$@")"
	source env/bin/activate && python spans2rpcs.py < $< | jq . > $@

output/data-2/traces-1711316915536_packets.json: data-2/trace.epyc3451.2024-03-24T21-30-38.pcap data-2/trace.thebeast.2024-03-24T17-30-40.pcap env/
	mkdir -p "$(shell dirname "$@")"
	source env/bin/activate && python extract_packet_ts.py 192.168.1.195=data-2/trace.epyc3451.2024-03-24T21-30-38.pcap 192.168.1.187=data-2/trace.thebeast.2024-03-24T17-30-40.pcap | jq . > $@

output/%_rpcs_packet_ts.json: output/%_packets.json output/%_rpcs.json
	mkdir -p "$(shell dirname "$@")"
	source env/bin/activate && python correct_rpcs_using_packets.py $^ > $@

output/%_rpc_latency_dist.png: output/%_rpcs.json env/
	mkdir -p "$(shell dirname "$@")"
	source env/bin/activate && cat $< | python plot_rpc_latency.py $@

output/%_rpc_latency_dist_with_skew_correct.png: output/%_rpcs.json
	mkdir -p "$(shell dirname "$@")"
	source env/bin/activate && cat $< | python correct_rpc_skew.py | python plot_rpc_latency.py $@

output/%_rpc_latency_dist_with_packet_correct.png: output/%_packets.json output/%_rpcs.json
	mkdir -p "$(shell dirname "$@")"
	source env/bin/activate && python correct_rpcs_using_packets.py $^ | python plot_rpc_latency.py $@

output/%_rpc_latency_dist_with_packet_and_skew_correct.png: output/%_packets.json output/%_rpcs.json
	mkdir -p "$(shell dirname "$@")"
	source env/bin/activate && python correct_rpcs_using_packets.py $^ | python correct_rpc_skew.py | python plot_rpc_latency.py $@

output/%_rpc_skew_dist.png: output/%_rpcs.json
	mkdir -p "$(shell dirname "$@")"
	source env/bin/activate && cat $< | python plot_rpc_skew.py $@

output/%_rpc_skew_dist_with_packet_correct.png: output/%_packets.json output/%_rpcs.json
	mkdir -p "$(shell dirname "$@")"
	source env/bin/activate && python correct_rpcs_using_packets.py $^ | python correct_rpc_skew.py | python plot_rpc_skew.py $@

