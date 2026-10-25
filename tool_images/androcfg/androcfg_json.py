# The AndroCFG CLI only writes a Markdown report; print the JSON report instead.
import json
import sys
import tempfile

from androcfg.call_graph_extractor import CFG

with tempfile.TemporaryDirectory() as output_dir:
    cfg = CFG(sys.argv[1], output_dir, "raw")
    cfg.compute_rules()
    print(json.dumps(cfg.generate_json_report(), default=str))
