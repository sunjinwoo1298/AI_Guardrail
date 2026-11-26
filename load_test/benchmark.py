"""Benchmark the proxy's prompt-injection decision on a labelled public dataset.

The repository's own security_eval.py uses ~110 hand-written prompts. A published number
needs public, independently labelled data. This harness runs the proxy's real block
decision (tripwires + ONNX classifier, behaviour scoring off) over any CSV or JSONL file
and reports precision, recall, F1, false-positive rate and latency, as JSON.

Datasets are not downloaded by this script; fetch them yourself and pass the file, e.g.
  * deepset/prompt-injections (Hugging Face; columns: text, label 1 = injection)
  * a JailbreakBench / lakera "gandalf" style export, or your own red-team corpus

Usage (from the repository root, conda env with requirements installed):

    python load_test/benchmark.py --file data/prompt_injections.csv \
        --text-field text --label-field label --positive 1 --output benchmark_report.json

``--positive`` lists the label values meaning "attack" (comma-separated). Use
``--group-field`` for a per-category breakdown and ``--limit`` for a quick run.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
import time
from collections import defaultdict
from typing import Dict, Iterable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("GROQ_API_KEY", "benchmark")
os.environ.setdefault("API_KEYS", "benchmark")


def load_rows(path: str, text_field: str, label_field: str, group_field: Optional[str]) -> List[dict]:
    rows = []
    if path.endswith((".jsonl", ".ndjson")):
        with open(path, encoding="utf-8") as handle:
            records: Iterable[dict] = (json.loads(line) for line in handle if line.strip())
            rows = list(records)
    elif path.endswith(".json"):
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
            rows = data if isinstance(data, list) else data.get("data", [])
    else:
        with open(path, encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
    out = []
    for row in rows:
        text, label = row.get(text_field), row.get(label_field)
        if not isinstance(text, str) or not text.strip() or label is None:
            continue
        out.append({"text": text, "label": str(label).strip().lower(),
                    "group": str(row.get(group_field, "all")) if group_field else "all"})
    return out


def _ratio(a: float, b: float) -> Optional[float]:
    return round(a / b, 4) if b else None


def scores(tp: int, fp: int, tn: int, fn: int) -> Dict[str, Optional[float]]:
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else None
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate": _ratio(fp, fp + tn), "accuracy": _ratio(tp + tn, tp + fp + tn + fn)}


def run(rows: List[dict], positive: set, decide) -> dict:
    counts = defaultdict(lambda: [0, 0, 0, 0])  # group -> tp, fp, tn, fn
    latencies, errors = [], []
    for row in rows:
        attack = row["label"] in positive
        started = time.perf_counter()
        blocked = decide(row["text"])
        latencies.append((time.perf_counter() - started) * 1000)
        index = (0 if blocked else 3) if attack else (1 if blocked else 2)
        counts[row["group"]][index] += 1
        counts["__all__"][index] += 1
        if blocked != attack and len(errors) < 50:
            errors.append({"kind": "missed_attack" if attack else "false_block", "group": row["group"],
                           "text": row["text"][:200]})
    latencies.sort()
    overall = scores(*counts.pop("__all__"))
    return {
        "samples": len(rows),
        "overall": overall,
        "by_group": {group: scores(*c) for group, c in sorted(counts.items())} if len(counts) > 1 else {},
        "latency_ms": {"p50": round(statistics.median(latencies), 2) if latencies else None,
                       "p95": round(latencies[int(0.95 * (len(latencies) - 1))], 2) if latencies else None,
                       "max": round(latencies[-1], 2) if latencies else None},
        "examples_of_errors": errors,
    }


def proxy_decision(use_classifier: bool = True):
    import app.security.prompt_guard as prompt_guard
    import app.security.risk_engine as risk_engine
    from app.security.risk_engine import calculate_risk_score, should_block_prompt

    risk_engine._behavior_risk = lambda text: (0.0, {"behavior_count": 0, "behavior_risk": 0.0})
    prompt_guard.INJECTION_VERIFIER_ENABLED = False
    if not use_classifier:
        prompt_guard._get_classifier = lambda: None

    def decide(text: str) -> bool:
        score, _pii, signals = calculate_risk_score(text)
        return bool(should_block_prompt(score, signals))

    return decide


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--file", required=True)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--label-field", default="label")
    parser.add_argument("--positive", default="1", help="label values meaning attack, comma-separated")
    parser.add_argument("--group-field")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--tripwires-only", action="store_true", help="skip the ML classifier")
    parser.add_argument("--output", help="write the JSON report here")
    args = parser.parse_args(argv)

    rows = load_rows(args.file, args.text_field, args.label_field, args.group_field)[: args.limit or None]
    if not rows:
        print("no usable rows (check --text-field / --label-field)", file=sys.stderr)
        return 2
    positive = {p.strip().lower() for p in args.positive.split(",") if p.strip()}
    report = run(rows, positive, proxy_decision(use_classifier=not args.tripwires_only))
    report["dataset"] = {"file": os.path.basename(args.file), "positive_labels": sorted(positive),
                         "mode": "tripwires only" if args.tripwires_only else "tripwires + ONNX classifier"}
    text = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
