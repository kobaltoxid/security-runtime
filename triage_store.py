"""SQLite persistence for resumable triage runs."""

import json
import sqlite3
import uuid


def init_db(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY, input_digest TEXT UNIQUE NOT NULL,
            finding_id TEXT NOT NULL, model TEXT NOT NULL, status TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, final_json TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS trace (
            run_id TEXT NOT NULL, sequence INTEGER NOT NULL, action TEXT NOT NULL,
            proposal_json TEXT NOT NULL, observation_json TEXT, created_at TEXT NOT NULL,
            PRIMARY KEY(run_id, sequence)
        )
    """)
    db.commit()


def load_or_create_run(db, input_digest, finding_id, model, now):
    columns = ("run_id", "input_digest", "finding_id", "model", "status", "final_json")
    row = db.execute(
        "SELECT run_id,input_digest,finding_id,model,status,final_json FROM runs WHERE input_digest=?",
        (input_digest,),
    ).fetchone()
    if row:
        return dict(zip(columns, row))
    run = {"run_id": uuid.uuid4().hex, "input_digest": input_digest,
           "finding_id": finding_id, "model": model, "status": "paused", "final_json": None}
    db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)",
               (run["run_id"], input_digest, finding_id, model, "paused", now, now, None))
    db.commit()
    return run


def load_traces(db, run_id):
    columns = ("sequence", "action", "proposal_json", "observation_json", "created_at")
    rows = db.execute(
        """SELECT sequence, action, proposal_json, observation_json, created_at
           FROM trace WHERE run_id=? ORDER BY sequence""", (run_id,)
    )
    return [dict(zip(columns, row)) for row in rows]


def observations_from(traces):
    observations = {}
    for trace in traces:
        if trace["observation_json"]:
            observation = json.loads(trace["observation_json"])
            observations[observation["kind"]] = observation
    return observations


def save_observation(db, run_id, sequence, proposal, observation, now):
    proposal_json = json.dumps(proposal)
    observation_json = json.dumps(observation)
    db.execute("""INSERT INTO trace
        (run_id, sequence, action, proposal_json, observation_json, created_at)
        VALUES (?,?,?,?,?,?)""",
               (run_id, sequence, proposal["action"], proposal_json, observation_json, now))
    db.execute("UPDATE runs SET updated_at=?,status='paused' WHERE run_id=?", (now, run_id))
    db.commit()
    return {"sequence": sequence, "action": proposal["action"], "proposal_json": proposal_json,
            "observation_json": observation_json, "created_at": now}


def save_final(db, run_id, sequence, proposal, now):
    proposal_json = json.dumps(proposal)
    final = {key: proposal[key] for key in ("verdict", "evidence_refs", "reason")}
    final_json = json.dumps(final)
    db.execute("""INSERT INTO trace
        (run_id, sequence, action, proposal_json, observation_json, created_at)
        VALUES (?,?,?,?,?,?)""",
               (run_id, sequence, "finish", proposal_json, None, now))
    db.execute("UPDATE runs SET status='final',final_json=?,updated_at=? WHERE run_id=?",
               (final_json, now, run_id))
    db.commit()
    return final_json, {"sequence": sequence, "action": "finish", "proposal_json": proposal_json,
                        "observation_json": None, "created_at": now}


def save_rejection(db, run_id, sequence, proposal, assessment, now):
    """Persist a rejected finish as an audit trace before a correction."""
    audited = {**proposal, "gate": assessment}
    proposal_json = json.dumps(audited)
    db.execute("""INSERT INTO trace
        (run_id, sequence, action, proposal_json, observation_json, created_at)
        VALUES (?,?,?,?,?,?)""",
               (run_id, sequence, "gate_rejection", proposal_json, None, now))
    db.execute("UPDATE runs SET updated_at=?,status='paused' WHERE run_id=?", (now, run_id))
    db.commit()
    return {"sequence": sequence, "action": "gate_rejection", "proposal_json": proposal_json,
            "observation_json": None, "created_at": now}


def output(run, traces, provider, policy_version):
    result = {"run_id": run["run_id"], "status": run["status"], "provider": provider,
              "policy_version": policy_version, "model": run["model"],
              "finding_id": run["finding_id"], "steps": len(traces)}
    if run["final_json"]:
        result["final"] = json.loads(run["final_json"])
    return result
