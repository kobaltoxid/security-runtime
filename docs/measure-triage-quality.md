# Measure triage quality

Compare SecDepth alone, a one-shot model review, and the gated review on the same findings. Start with the mock benchmark to see how the scorer matches labels to results. You only need Python 3 and the `security-runtime` checkout.

## Run a no-model demo

Run these commands from the `security-runtime` checkout. The demo creates two saved scan bundles with synthetic evidence, one for a source finding and one for an artifact finding. It exercises the real acceptance gate with scripted model replies and makes zero live model calls.

```sh
benchmark_dir="$(mktemp -d)"
python3 -m benchmarks.demo --output "$benchmark_dir"
python3 -m json.tool "$benchmark_dir/comparison.json"
python3 benchmarks/score.py \
  "$benchmark_dir/labels.json" "$benchmark_dir/runs.json" \
  > "$benchmark_dir/comparison-rerun.json"
```

The demo writes `labels.json` with the expected verdicts, `runs.json` with the three sets of results, and `comparison.json` with the scores. The `source/` and `artifact/` directories each contain a saved report, checks, and a `triage.db` checkpoint. The last command runs the scorer again from the saved labels and results.

In the source case, the gate corrects a scripted verdict that conflicts with the saved checks. In the artifact case, the missing checks lead to `insufficient_evidence`. The gated result should match both expected verdicts. These scores describe the synthetic cases only. The model call counts represent scripted replies.

## Build a real benchmark

Keep a versioned set of findings that SecDepth flagged for review. Record the scan input and exact source revision or artifact digest for each finding. A reviewer must assign the expected verdict from the saved evidence before scoring. Keep cases used to tune prompts out of the published dataset.

Use the directory containing a scan's saved `report.json` and `checks.json`. Keep one directory per scan so a later run can reuse the same evidence.

Set `scan_dir` to a saved scan directory and list its flagged advisory IDs.

```sh
scan_dir=/path/to/saved-scan
python3 - "$scan_dir/report.json" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text())
for finding in report["vulnerabilities"]:
    if (finding.get("review") or {}).get("needed") is True:
        print(finding["id"])
PY
```

For the SecDepth-only result, record a flagged finding as `insufficient_evidence`. The flag means SecDepth left it open for review.

For each flagged finding, add a case to `labels.json` with an `id`, `target_kind` (`source` or `artifact`), `expected_verdict`, the `scan_dir` that holds its saved scan, and its `advisory` ID. Use a distinct case ID for each finding and scan pair, even when two scans report the same advisory.

Run the three approaches from the repository root. The runner reads each case's scan from the directory next to `labels.json` unless you pass `--cases-root`.

```sh
python3 -m benchmarks.run path/to/labels.json --output .state/benchmark-runs
python3 benchmarks/score.py path/to/labels.json .state/benchmark-runs/runs.json \
  > .state/benchmark-runs/comparison.json
```

The runner makes model calls through the authenticated personal `claude2` command; pass `--provider` and `--model` to change them. Add `--limit 2` for a short trial run. Each approach works from the same saved scan:

- **SecDepth alone** records every flagged finding as `insufficient_evidence`, because SecDepth left it open for review.
- **One-shot review** sends the checks and affected components in one request and accepts the model's verdict without a correction.
- **Gated review** runs the triage worker with its evidence requests, acceptance gate, and one correction. Its SQLite databases are kept in `gated/`.

A verdict other than `insufficient_evidence` counts as an unsupported claim when the acceptance gate cannot verify it from the observed checks. The runner records cost as unknown because the model transport does not report it.

The runner saves each case's result in `cases/` as soon as it finishes. Run the same command again after an interruption, and it reuses the saved results instead of calling the model again.
