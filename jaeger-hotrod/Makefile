
OUTPUT_FILES += output/data-1/traces-1711294619583_spans.json
OUTPUT_FILES += output/data-2/traces-1711316915536_spans.json

.PHONY: all
all: $(OUTPUT_FILES)

.PHONY: venv
venv: env/

env/:
	python3 -m venv env
	source env/bin/activate && pip install --upgrade pip
	source env/bin/activate && pip install dpkt matplotlib numpy

output/:
	mkdir -p output


.PHONY: clean
clean:
	rm -rf output/
	rm -rf env/

output/%_spans.json: %.json 
	mkdir -p "$(shell dirname "$@")"
	source env/bin/activate && python traces2spans.py < $< > $@
