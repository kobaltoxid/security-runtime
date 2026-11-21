"""Load a finding and constrain the evidence and decisions in its review."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from scan_reports import flagged_for_review

ACTIONS = {"inspect_checks", "inspect_components", "finish"}
VERDICTS = {"evidence_supports_report", "evidence_conflicts_with_report", "insufficient_evidence"}


@dataclass(frozen=True)
class ReviewInput:
    finding: dict
    components: dict
    checks: dict | None
    digest: str


def input_digest(files, finding_id, model, provider, policy_version):
    digest = hashlib.sha256()
    for name in ("report.json", "checks.json"):
        if name in files:
            payload = files[name]
            digest.update(name.encode() + b"\0" + len(payload).to_bytes(8, "big") + payload)
    digest.update("\0".join((provider, policy_version, finding_id, model)).encode())
    return digest.hexdigest()


def select_finding(report, finding_id):
    findings = report.get("vulnerabilities") if isinstance(report, dict) else None
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise ValueError("report.json has an invalid vulnerabilities list")
    if not finding_id:
        for finding in findings:
            if flagged_for_review(finding):
                return finding
        raise ValueError("report has no finding flagged for review")

    finding = next((item for item in findings if item.get("id") == finding_id), None)
    if finding is None:
        raise ValueError(f"finding {finding_id} was not found")
    if not flagged_for_review(finding):
        raise ValueError(f"finding {finding_id} is not flagged for review")
    return finding


def load_review(directory, finding_id, model, provider, policy_version):
    files = {"report.json": (directory / "report.json").read_bytes()}
    checks_file = directory / "checks.json"
    if checks_file.is_file():
        files["checks.json"] = checks_file.read_bytes()
    try:
        report = json.loads(files["report.json"])
        checks = json.loads(files["checks.json"]) if "checks.json" in files else None
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"triage input is unreadable: {exc}") from exc

    finding = select_finding(report, finding_id)
    selected_id = finding.get("id")
    if not isinstance(selected_id, str) or not selected_id:
        raise ValueError("flagged finding has no advisory ID")
    records = report.get("components", [])
    if not isinstance(records, list):
        raise ValueError("report.json has an invalid components list")
    components = {item.get("id"): item for item in records if isinstance(item, dict)}
    affected = finding.get("affected_component_ids") or []
    if not isinstance(affected, list) or not all(isinstance(item, str) and item in components for item in affected):
        raise ValueError("finding has an unknown affected component")
    digest = input_digest(files, selected_id, model, provider, policy_version)
    return ReviewInput(finding, components, checks, digest)


def request_for(review, observations):
    finding = review.finding
    exploitability = finding.get("exploitability") or {}
    return {
        "finding": {
            "id": finding["id"],
            "summary": finding.get("summary"),
            "applicability": finding.get("applicability"),
            "affected_component_ids": finding.get("affected_component_ids", []),
            "exploitability": {key: exploitability.get(key) for key in ("presence", "reachability", "confidence")},
            "review": {"needed": True},
        },
        "available_actions": sorted(ACTIONS),
        "observations": observations,
        "evidence_available": {"checks": review.checks is not None, "components": bool(review.components)},
    }


def rejected_action(observations, reason):
    return {"action": "finish", "verdict": "insufficient_evidence", "evidence_refs": sorted(observations), "reason": reason}


def validate_action(proposal, review, observations):
    if not isinstance(proposal, dict):
        raise ValueError("model returned an invalid action")
    action = proposal.get("action")
    if not isinstance(action, str) or action not in ACTIONS:
        raise ValueError("model returned an invalid action")
    if action != "finish":
        if set(proposal) != {"action"}:
            raise ValueError("model returned unexpected action fields")
        evidence_key = "checks" if action == "inspect_checks" else "components"
        if len(observations) >= 2 or evidence_key in observations or (evidence_key == "checks" and review.checks is None):
            return rejected_action(observations, "The model repeated an unavailable or already observed evidence request.")
        return proposal

    if set(proposal) - {"action", "verdict", "evidence_refs", "reason"}:
        raise ValueError("model returned unexpected action fields")
    verdict, refs, reason = proposal.get("verdict"), proposal.get("evidence_refs"), proposal.get("reason")
    if verdict not in VERDICTS or not isinstance(refs, list) or not all(isinstance(item, str) for item in refs):
        raise ValueError("finish requires a valid verdict and evidence_refs")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        raise ValueError("finish requires a concise reason")
    if not set(refs).issubset(observations):
        return rejected_action(observations, "The model referenced evidence that it did not inspect.")
    if verdict != "insufficient_evidence" and not refs:
        return rejected_action(observations, "The model supplied no reference to observed evidence.")
    return {**proposal, "reason": reason.strip()}


def observation_for(action, review):
    finding = review.finding
    affected = finding.get("affected_component_ids") or []
    if action == "inspect_checks":
        finding_id = finding["id"]
        allowed = {"advisory_id", "component_id", "evidence", "proposed_reachability", "scope", "confidence"}
        results = review.checks.get("results", []) if isinstance(review.checks, dict) else []
        affected_ids = set(affected)
        records = [
            {key: item[key] for key in allowed if key in item}
            for item in results
            if isinstance(item, dict) and item.get("advisory_id") == finding_id
            and item.get("component_id") in affected_ids
        ]
        return {"kind": "checks", "advisory_id": finding_id, "results": records}
    fields = ("id", "name", "ecosystem", "version", "scope", "direct", "depends_on")
    return {
        "kind": "components",
        "components": [{key: review.components[item].get(key) for key in fields} for item in affected],
    }
