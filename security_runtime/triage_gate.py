"""Deterministic acceptance gate for model reachability verdicts."""


KNOWN_REACHABILITY = {"reachable", "not-reachable", "conditional"}


def _known(value):
    return isinstance(value, str) and value in KNOWN_REACHABILITY


def _has_evidence(value):
    return (isinstance(value, list) and bool(value)
            and all(isinstance(item, str) and item.strip() for item in value))


def _check_facts(review, observations):
    finding = review.finding
    reported = (finding.get("exploitability") or {}).get("reachability")
    if not _known(reported):
        return None, "the report has no known reachability"
    checks = observations.get("checks")
    if not isinstance(checks, dict):
        return None, "checks evidence was not inspected"
    rows = checks.get("results")
    if not isinstance(rows, list) or not rows:
        return None, "checks evidence is empty"
    affected = finding.get("affected_component_ids") or []
    if not affected:
        return None, "the finding has no affected components"
    by_component = {component: [] for component in affected}
    for row in rows:
        if not isinstance(row, dict):
            continue
        component = row.get("component_id")
        if component not in by_component:
            continue
        evidence = row.get("evidence")
        proposed = row.get("proposed_reachability")
        if not _has_evidence(evidence) or not _known(proposed):
            return None, f"checks evidence for {component} is missing or unknown"
        by_component[component].append(proposed)
    if any(not values for values in by_component.values()):
        return None, "checks evidence does not cover every affected component"
    if any(len(set(values)) != 1 for values in by_component.values()):
        return None, "checks evidence has mixed reachability for a component"
    proposed = {values[0] for values in by_component.values()}
    if len(proposed) != 1:
        return None, "checks evidence has mixed reachability across components"
    return (reported, proposed.pop(), len(affected)), None


def assess(proposal, review, observations):
    """Return acceptance and a safe reason derived only from observed facts."""
    verdict = proposal.get("verdict") if isinstance(proposal, dict) else None
    if verdict == "insufficient_evidence":
        return {"accepted": True, "actionable": False, "reason": proposal["reason"]}
    if verdict not in {"evidence_supports_report", "evidence_conflicts_with_report"}:
        return {"accepted": False, "actionable": False, "reason": "The model supplied no usable verdict."}
    refs = proposal.get("evidence_refs", [])
    if "checks" not in refs:
        return {"accepted": False, "actionable": False,
                "reason": "The acceptance gate requires the cited checks observation."}
    facts, failure = _check_facts(review, observations)
    if failure:
        return {"accepted": False, "actionable": False,
                "reason": f"The acceptance gate could not verify the verdict: {failure}."}
    reported, proposed, component_count = facts
    agrees = proposed == reported
    expected = "evidence_supports_report" if agrees else "evidence_conflicts_with_report"
    if verdict != expected:
        return {"accepted": False, "actionable": True,
                "reason": "The acceptance gate found that the cited checks support a different reachability verdict."}
    outcome = "supports" if agrees else "conflicts with"
    reason = (f"Verified checks for {component_count} affected component(s) report "
              f"reachability '{proposed}', which {outcome} the reported reachability "
              f"'{reported}'.")
    return {"accepted": True, "actionable": False, "reason": reason,
            "proposal": {**proposal, "reason": reason}}
