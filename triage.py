#!/usr/bin/env python3
"""Bounded, resumable model triage for one SecDepth finding."""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import pathlib
import sqlite3
import sys
import uuid

try:
    import triage_model
except ImportError:
    triage_model = None

VERDICTS = {"evidence_supports_report", "evidence_conflicts_with_report", "insufficient_evidence"}
ACTIONS = {"inspect_checks", "inspect_components", "finish"}
DEFAULT_PROVIDER = "claude2"
PROVIDERS = {DEFAULT_PROVIDER, "claude-oauth"}
POLICY_VERSION = "triage-policy-1"  # Bump when evidence or verdict policy changes.


def timestamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest_input(directory, finding_id, model, snapshot=None, provider=DEFAULT_PROVIDER):
    digest = hashlib.sha256()
    raw = snapshot[2] if snapshot is not None else {}
    for name in ("report.json", "checks.json"):
        if name in raw:
            payload = raw[name]
            digest.update(name.encode() + b"\0" + len(payload).to_bytes(8, "big") + payload)
    digest.update(provider.encode() + b"\0" + POLICY_VERSION.encode() + b"\0" + finding_id.encode() + b"\0" + model.encode())
    return digest.hexdigest()


def read_snapshot(directory):
    raw = {"report.json": (directory / "report.json").read_bytes()}
    checks_path = directory / "checks.json"
    if checks_path.is_file():
        raw["checks.json"] = checks_path.read_bytes()
    try:
        report = json.loads(raw["report.json"])
        checks = json.loads(raw["checks.json"]) if "checks.json" in raw else None
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("triage input is unreadable: %s" % exc) from exc
    return report, checks, raw


def load_input(directory, finding_id, snapshot=None):
    if snapshot is None:
        try:
            report, checks, _raw = read_snapshot(directory)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("triage input is unreadable: %s" % exc) from exc
    else:
        report, checks, _raw = snapshot
    try:
        findings = report.get("vulnerabilities")
    except AttributeError as exc:
        raise ValueError("report.json has an invalid root") from exc
    if not isinstance(findings, list):
        raise ValueError("report.json has no vulnerabilities list")
    finding = next((item for item in findings if item.get("id") == finding_id), None)
    if finding is None:
        raise ValueError("finding %s was not found" % finding_id)
    if not finding.get("review", {}).get("needed"):
        raise ValueError("finding %s is not flagged for review" % finding_id)
    components = {item.get("id"): item for item in report.get("components", []) if isinstance(item, dict)}
    affected = finding.get("affected_component_ids") or []
    if not all(isinstance(item, str) and item in components for item in affected):
        raise ValueError("finding has an unknown affected component")
    return report, finding, components, checks


def first_review(directory, snapshot=None):
    report = (snapshot or read_snapshot(directory))[0]
    for item in report.get("vulnerabilities", []):
        if item.get("review", {}).get("needed"):
            return item.get("id")
    raise ValueError("report has no finding flagged for review")


def request_for(finding, components, checks, observations):
    return {
        "finding": {
            "id": finding["id"],
            "summary": finding.get("summary"),
            "applicability": finding.get("applicability"),
            "affected_component_ids": finding.get("affected_component_ids", []),
            "exploitability": {k: finding.get("exploitability", {}).get(k) for k in ("presence", "reachability", "confidence")},
            "review": {"needed": bool(finding.get("review", {}).get("needed"))},
        },
        "available_actions": sorted(ACTIONS),
        "observations": observations,
        "evidence_available": {"checks": checks is not None, "components": bool(components)},
    }


def clean_action(proposal):
    if not isinstance(proposal, dict) or proposal.get("action") not in ACTIONS:
        raise ValueError("model returned an invalid action")
    allowed = {"action"} if proposal["action"] != "finish" else {"action", "verdict", "evidence_refs", "reason"}
    if set(proposal) - allowed:
        raise ValueError("model returned unexpected action fields")
    if proposal["action"] != "finish":
        return {"action": proposal["action"]}
    verdict = proposal.get("verdict")
    refs = proposal.get("evidence_refs")
    reason = proposal.get("reason")
    if verdict not in VERDICTS or not isinstance(refs, list) or not all(isinstance(x, str) for x in refs):
        raise ValueError("finish requires a valid verdict and evidence_refs")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        raise ValueError("finish requires a concise reason")
    return {"action": "finish", "verdict": verdict, "evidence_refs": refs, "reason": reason.strip()}


@contextlib.contextmanager
def locked(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def init_db(db):
    db.execute("CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, input_digest TEXT UNIQUE NOT NULL, finding_id TEXT NOT NULL, model TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, final_json TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS trace (run_id TEXT NOT NULL, sequence INTEGER NOT NULL, action TEXT NOT NULL, proposal_json TEXT NOT NULL, observation_json TEXT, created_at TEXT NOT NULL, PRIMARY KEY(run_id, sequence))")
    db.commit()


def output(run, traces, provider=DEFAULT_PROVIDER):
    result = {"run_id": run["run_id"], "status": run["status"], "provider": provider, "policy_version": POLICY_VERSION, "model": run["model"], "finding_id": run["finding_id"], "steps": len(traces)}
    if run["final_json"]:
        result["final"] = json.loads(run["final_json"])
    return result


def _triage_step(directory, db_path, finding_id=None, model="haiku", one_step=False, snapshot=None, provider=DEFAULT_PROVIDER):
    directory = pathlib.Path(directory).resolve()
    if not directory.is_dir():
        raise ValueError("artifact directory does not exist")
    selected_id = finding_id or first_review(directory, snapshot)
    _report, finding, components, checks = load_input(directory, selected_id, snapshot)
    if provider not in PROVIDERS:
        raise ValueError("unsupported model provider")
    key = digest_input(directory, selected_id, model, snapshot, provider)
    with locked(db_path.with_suffix(db_path.suffix + ".lock")):
        db = sqlite3.connect(db_path)
        try:
            init_db(db)
            columns = ("run_id", "input_digest", "finding_id", "model", "status", "final_json")
            row = db.execute("SELECT run_id,input_digest,finding_id,model,status,final_json FROM runs WHERE input_digest=?", (key,)).fetchone()
            if row:
                run = dict(zip(columns, row))
            else:
                run = {"run_id": uuid.uuid4().hex, "input_digest": key, "finding_id": selected_id, "model": model, "status": "paused", "final_json": None}
                now = timestamp()
                db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)", (run["run_id"], key, selected_id, model, "paused", now, now, None))
                db.commit()
            traces = [dict(zip(("sequence", "action", "proposal_json", "observation_json", "created_at"), x)) for x in db.execute("SELECT sequence,action,proposal_json,observation_json,created_at FROM trace WHERE run_id=? ORDER BY sequence", (run["run_id"],))]
            if run["status"] == "final":
                return output(run, traces, provider)
            observations = {json.loads(t["observation_json"])["kind"]: json.loads(t["observation_json"]) for t in traces if t["observation_json"]}
            if triage_model is None or not hasattr(triage_model, "choose"):
                raise RuntimeError("triage_model.choose is unavailable")
            try:
                request = request_for(finding, components, checks, observations)
                if provider == DEFAULT_PROVIDER:
                    raw_proposal = triage_model.choose(model, request)
                else:
                    raw_proposal = triage_model.choose(model, request, provider=provider)
                proposal = clean_action(raw_proposal)
            except (TypeError, ValueError) as exc:
                proposal = {"action": "finish", "verdict": "insufficient_evidence", "evidence_refs": sorted(observations), "reason": "The model action was rejected by the runtime: %s." % str(exc)[:300]}
            if proposal["action"] in {"inspect_checks", "inspect_components"}:
                observation_key = "checks" if proposal["action"] == "inspect_checks" else "components"
                if len(observations) >= 2 or observation_key in observations or (proposal["action"] == "inspect_checks" and checks is None):
                    proposal = {"action": "finish", "verdict": "insufficient_evidence", "evidence_refs": sorted(observations), "reason": "The model repeated an unavailable or already observed evidence request."}
                else:
                    if proposal["action"] == "inspect_checks":
                        affected = set(finding.get("affected_component_ids", []))
                        allowed = {"advisory_id", "component_id", "evidence", "proposed_reachability", "scope", "confidence"}
                        records = [{k: item.get(k) for k in allowed if k in item} for item in checks.get("results", []) if isinstance(item, dict) and item.get("advisory_id") == selected_id and item.get("component_id") in affected] if isinstance(checks, dict) else []
                        observation = {"kind": "checks", "advisory_id": selected_id, "results": records}
                    else:
                        observation = {"kind": "components", "components": [{k: components[c].get(k) for k in ("id", "name", "ecosystem", "version", "scope", "direct", "depends_on")} for c in finding.get("affected_component_ids", [])]}
                    sequence = len(traces) + 1
                    db.execute("INSERT INTO trace VALUES (?,?,?,?,?,?)", (run["run_id"], sequence, proposal["action"], json.dumps(proposal), json.dumps(observation), timestamp()))
                    db.execute("UPDATE runs SET updated_at=?,status='paused' WHERE run_id=?", (timestamp(), run["run_id"]))
                    db.commit()
                    traces.append({"sequence": sequence, "action": proposal["action"], "proposal_json": json.dumps(proposal), "observation_json": json.dumps(observation), "created_at": timestamp()})
                    if one_step:
                        return output(run, traces, provider)
                    return output(run, traces, provider)
            refs = set(proposal.get("evidence_refs", []))
            if not refs.issubset(observations):
                proposal = {"action": "finish", "verdict": "insufficient_evidence", "evidence_refs": sorted(observations), "reason": "The model referenced evidence that it did not inspect."}
            elif proposal["verdict"] != "insufficient_evidence" and not refs:
                proposal = {"action": "finish", "verdict": "insufficient_evidence", "evidence_refs": sorted(observations), "reason": "The model supplied no reference to observed evidence."}
            sequence = len(traces) + 1
            db.execute("INSERT INTO trace VALUES (?,?,?,?,?,?)", (run["run_id"], sequence, "finish", json.dumps(proposal), None, timestamp()))
            final = {k: proposal[k] for k in ("verdict", "evidence_refs", "reason")}
            db.execute("UPDATE runs SET status='final',final_json=?,updated_at=? WHERE run_id=?", (json.dumps(final), timestamp(), run["run_id"]))
            db.commit()
            run["status"], run["final_json"] = "final", json.dumps(final)
            traces.append({"sequence": sequence, "action": "finish", "proposal_json": json.dumps(proposal), "observation_json": None, "created_at": timestamp()})
            return output(run, traces, provider)
        finally:
            db.close()


def triage(directory, db_path, finding_id=None, model="haiku", one_step=False, provider=DEFAULT_PROVIDER):
    directory = pathlib.Path(directory).resolve()
    snapshot = read_snapshot(directory)
    result = _triage_step(directory, db_path, finding_id, model, one_step, snapshot, provider)
    while not one_step and result["status"] == "paused":
        result = _triage_step(directory, db_path, finding_id or result["finding_id"], model, one_step, snapshot, provider)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("artifact_dir")
    parser.add_argument("--db", required=True, type=pathlib.Path)
    parser.add_argument("--finding")
    parser.add_argument("--model", default="haiku")
    parser.add_argument("--provider", choices=sorted(PROVIDERS), default=DEFAULT_PROVIDER)
    parser.add_argument("--step", action="store_true")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(triage(args.artifact_dir, args.db, args.finding, args.model, args.step, args.provider), sort_keys=True))
    except KeyboardInterrupt:
        print(json.dumps({"status": "paused", "reason": "interrupted"}))
        return 130
    except (RuntimeError, ValueError, OSError, sqlite3.Error) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
