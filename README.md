# TraceDoppler

Experimental data is in [jaeger-hotrod/data-2](jaeger-hotrod/data-2).

To run the analysis pipeline, make sure `python`, `pip`, `venv`, and `jq` are installed, then run (from the repo root):

```shell
cd jaeger-hotrod
make env
source env/bin/activate
python pipeline.py
```

