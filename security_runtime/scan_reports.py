"""Report, history, and comparison helpers for security-runtime scans."""

import json


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def flagged_for_review(finding):
    review = finding.get("review")
    return isinstance(review, dict) and bool(review.get("needed"))


def report_signature(report):
    result = {}
    for finding in report.get("vulnerabilities", []):
        result[finding["id"]] = {
            "applicability": finding.get("applicability"),
            "components": sorted(finding["affected_component_ids"]),
            "reachability": finding["exploitability"].get("reachability"),
            "review": finding["review"].get("needed"),
            "severity": (finding.get("cvss") or {}).get("severity"),
            "update_status": finding.get("update_status"),
            "recommended_target_version": finding.get("recommended_target_version"),
        }
    return result


def compare(observed, baseline, current, partial):
    complete = report_signature(baseline or {})
    old = {**complete, **report_signature(observed or {})}
    new = report_signature(current or {})
    added = sorted(set(new) - set(old))
    changed = sorted(k for k in set(new) & set(old) if new[k] != old[k])
    missing = sorted(set(complete) - set(new))
    return {"new": added, "changed": changed, "missing": [] if partial else missing,
            "missing_suppressed": bool(partial and missing)}


def scan_history(runs):
    published = sorted((p for p in runs.iterdir() if p.name.isascii() and p.name.isdecimal()), reverse=True)
    observed = None
    complete = None
    for run in published:
        summary = read_json(run / "summary.json")
        if summary["status"] in {"complete", "partial"} and observed is None:
            observed = summary, read_json(run / "report.json")
        if summary["status"] == "complete":
            complete = observed if observed[0] == summary else (summary, read_json(run / "report.json"))
            break
    next_sequence = int(published[0].name) + 1 if published else 1
    return f"{next_sequence:012d}", observed, complete


def validated_report(directory):
    report = read_json(directory / "report.json")
    if not (directory / "report.html").is_file():
        raise ValueError("missing HTML report")
    target = report["report"]["target"]
    findings = report["vulnerabilities"]
    if (not isinstance(target["coverage_complete"], bool)
            or any(not isinstance(target[key], list) for key in ("lookup_failures", "not_queried"))
            or not isinstance(findings, list)):
        raise ValueError("invalid report structure")
    signature = report_signature(report)
    if len(signature) != len(findings) or any(not isinstance(key, str) or not key for key in signature):
        raise ValueError("advisory IDs must be unique nonempty strings")
    return report


def summarize_scan(report, reason, observed, baseline):
    if report is None:
        return {"status": "failed", "reason": reason}
    target = report["report"]["target"]
    partial = (not target.get("coverage_complete", False)
               or bool(target.get("lookup_failures")) or bool(target.get("not_queried"))
               or bool(target.get("offline")))
    diff = compare(observed[1] if observed else None, baseline[1] if baseline else None, report, partial)
    return {
        "status": "partial" if partial else "complete",
        "reason": reason,
        "assessment_complete": not partial,
        "diff": diff,
        "coverage_complete": target.get("coverage_complete"),
        "coverage": target.get("coverage"),
        "lookup_failures": target.get("lookup_failures", []),
        "unqueried": target.get("not_queried", []),
        "offline": bool(target.get("offline")),
        "review_needed": sum(flagged_for_review(finding) for finding in report["vulnerabilities"]),
    }
