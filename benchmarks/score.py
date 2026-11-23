#!/usr/bin/env python3
"""Score deterministic SecDepth benchmark runs against human labels."""

from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import re
import sys


VERDICTS = {
    "evidence_supports_report",
    "evidence_conflicts_with_report",
    "insufficient_evidence",
}
MODES = ("secdepth", "one_shot", "gated")


class InputError(ValueError):
    """Benchmark input does not satisfy the scoring contract."""


def _object(value, name):
    if not isinstance(value, dict):
        raise InputError(f"{name} must be an object")
    return value


def _schema_version(value, name):
    if type(value.get("schema_version")) is not int or value.get("schema_version") != 1:
        raise InputError(f"{name}.schema_version must be 1")


def _dataset_id(value, name):
    dataset_id = value.get("dataset_id")
    if not isinstance(dataset_id, str) or not dataset_id.strip():
        raise InputError(f"{name}.dataset_id must be a nonblank string")
    return dataset_id


def _nonnegative_int(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InputError(f"{name} must be a nonnegative integer")


def _decimal(value, name):
    if value is None:
        return None
    if not isinstance(value, str):
        raise InputError(f"{name} must be a decimal string or null")
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value):
        raise InputError(f"{name} must be a nonnegative decimal string or null")
    try:
        number = Decimal(value)
    except InvalidOperation:
        raise InputError(f"{name} must be a decimal string or null") from None
    if not number.is_finite() or number < 0:
        raise InputError(f"{name} must be a nonnegative decimal string or null")
    return number


def _labels(value):
    value = _object(value, "labels")
    _schema_version(value, "labels")
    dataset_id = _dataset_id(value, "labels")
    cases = value.get("cases")
    if not isinstance(cases, list):
        raise InputError("labels.cases must be a list")
    if not cases:
        raise InputError("labels.cases must not be empty")
    result = {}
    for index, case in enumerate(cases):
        case = _object(case, f"labels.cases[{index}]")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise InputError(f"labels.cases[{index}].id must be a nonblank string")
        if case_id in result:
            raise InputError(f"duplicate case id: {case_id}")
        if not isinstance(case.get("target_kind"), str) or case.get("target_kind") not in {"source", "artifact"}:
            raise InputError(f"labels.cases[{index}].target_kind is invalid")
        if not isinstance(case.get("expected_verdict"), str) or case.get("expected_verdict") not in VERDICTS:
            raise InputError(f"labels.cases[{index}].expected_verdict is invalid")
        result[case_id] = case
    return dataset_id, result


def _runs(value, dataset_id, labels):
    value = _object(value, "runs")
    _schema_version(value, "runs")
    if _dataset_id(value, "runs") != dataset_id:
        raise InputError("labels and runs dataset_id differ")
    run_modes = value.get("runs")
    if not isinstance(run_modes, dict) or set(run_modes) != set(MODES):
        raise InputError("runs.runs must contain exactly secdepth, one_shot, and gated")
    parsed = {}
    expected_ids = set(labels)
    for mode in MODES:
        entries = run_modes[mode]
        if not isinstance(entries, list):
            raise InputError(f"runs.runs.{mode} must be a list")
        mode_results = {}
        for index, entry in enumerate(entries):
            entry = _object(entry, f"runs.runs.{mode}[{index}]")
            case_id = entry.get("id")
            if not isinstance(case_id, str) or not case_id.strip():
                raise InputError(f"runs.runs.{mode}[{index}].id must be a nonblank string")
            if case_id in mode_results:
                raise InputError(f"duplicate case id in {mode}: {case_id}")
            if case_id not in labels:
                raise InputError(f"unknown case id in {mode}: {case_id}")
            if not isinstance(entry.get("verdict"), str) or entry.get("verdict") not in VERDICTS:
                raise InputError(f"runs.runs.{mode}[{index}].verdict is invalid")
            for field in ("unsupported_claims", "elapsed_ms", "model_calls"):
                _nonnegative_int(entry.get(field), f"runs.runs.{mode}[{index}].{field}")
            if "cost_usd" not in entry:
                raise InputError(f"runs.runs.{mode}[{index}].cost_usd is required")
            cost = _decimal(entry["cost_usd"], f"runs.runs.{mode}[{index}].cost_usd")
            mode_results[case_id] = (entry, cost)
        if set(mode_results) != expected_ids:
            raise InputError(f"{mode} does not contain the complete labeled case set")
        parsed[mode] = mode_results
    return parsed


def _score_mode(labels, entries):
    cases = []
    correct = answered_correct = abstentions = unsupported = elapsed = model_calls = known_costs = 0
    known_cost_total = Decimal(0)
    for case_id in sorted(labels):
        label = labels[case_id]
        entry, cost = entries[case_id]
        verdict = entry["verdict"]
        is_abstention = verdict == "insufficient_evidence"
        is_correct = verdict == label["expected_verdict"]
        correct += is_correct
        answered_correct += is_correct and not is_abstention
        abstentions += is_abstention
        unsupported += entry["unsupported_claims"]
        elapsed += entry["elapsed_ms"]
        model_calls += entry["model_calls"]
        if cost is not None:
            known_costs += 1
            known_cost_total += cost
        cases.append({
            "id": case_id,
            "target_kind": label["target_kind"],
            "expected_verdict": label["expected_verdict"],
            "verdict": verdict,
            "correct": is_correct,
            "abstention": is_abstention,
            "unsupported_claims": entry["unsupported_claims"],
            "elapsed_ms": entry["elapsed_ms"],
            "model_calls": entry["model_calls"],
            "cost_usd": None if cost is None else str(cost),
        })
    total = len(cases)
    answered = total - abstentions
    return {
        "counts": {"total": total, "correct": correct, "incorrect": total - correct,
                   "abstentions": abstentions, "answered": answered},
        "accuracy": correct / total if total else None,
        "answered_accuracy": answered_correct / answered if answered else None,
        "unsupported_claims": unsupported,
        "elapsed_ms": elapsed,
        "model_calls": model_calls,
        "known_cost_count": known_costs,
        "known_cost_total_usd": None if not known_costs else str(known_cost_total),
        "cases": cases,
    }


def score(labels_value, runs_value):
    dataset_id, labels = _labels(labels_value)
    runs = _runs(runs_value, dataset_id, labels)
    return {"dataset_id": dataset_id, "modes": {
        mode: _score_mode(labels, runs[mode]) for mode in MODES
    }}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("usage: score.py LABELS.json RUNS.json", file=sys.stderr)
        return 2
    try:
        labels = json.loads(Path(argv[0]).read_text())
        runs = json.loads(Path(argv[1]).read_text())
        output = score(labels, runs)
    except (OSError, json.JSONDecodeError, InputError) as exc:
        print(f"score.py: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
