"""Post a pull request comment only after a person approves its exact text.

A request records the exact comment the runtime wants to post. Its digest covers
the repository, pull request, head commit, and body, so an approval applies only
to that payload. Posting checks the approval, the current pull request head, and
any comment already posted for the same digest.
"""

from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess

from .runtime_support import exclusive_lock, utc_timestamp

MARKER = "<!-- security-runtime-write: {digest} -->"
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
MAX_BODY = 60000


class WriteGateError(ValueError):
    pass


def comment_action(repository, pull_request, head_sha, body):
    if not REPOSITORY_PATTERN.fullmatch(repository or ""):
        raise WriteGateError("repository must be owner/name")
    if not isinstance(pull_request, int) or pull_request <= 0:
        raise WriteGateError("pull request must be a positive number")
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha or ""):
        raise WriteGateError("head SHA must be a full lowercase commit SHA")
    if not isinstance(body, str) or not body.strip() or len(body) > MAX_BODY:
        raise WriteGateError(f"body must be non-empty and at most {MAX_BODY} characters")
    return {"kind": "pr_comment", "repository": repository, "pull_request": pull_request,
            "head_sha": head_sha, "body": body}


def digest_action(action):
    canonical = json.dumps(action, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def init_db(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS write_requests (
            digest TEXT PRIMARY KEY, action_json TEXT NOT NULL, status TEXT NOT NULL,
            created_at TEXT NOT NULL, approver TEXT, approved_at TEXT,
            comment_id INTEGER, comment_url TEXT, completed_at TEXT
        )
    """)
    db.commit()


def load(db, digest):
    columns = ("digest", "action_json", "status", "created_at", "approver", "approved_at",
               "comment_id", "comment_url", "completed_at")
    row = db.execute(f"SELECT {','.join(columns)} FROM write_requests WHERE digest=?", (digest,)).fetchone()
    if row is None:
        raise WriteGateError(f"no write request {digest}")
    request = dict(zip(columns, row))
    request["action"] = json.loads(request.pop("action_json"))
    return request


def propose(db, action, now):
    digest = digest_action(action)
    db.execute("INSERT OR IGNORE INTO write_requests (digest, action_json, status, created_at) VALUES (?,?,?,?)",
               (digest, json.dumps(action, sort_keys=True), "pending", now))
    db.commit()
    return load(db, digest)


def approve(db, digest, approver, now):
    request = load(db, digest)
    if not approver:
        raise WriteGateError("approval needs the approver's GitHub login")
    if request["status"] != "pending":
        return request
    db.execute("UPDATE write_requests SET status='approved', approver=?, approved_at=? WHERE digest=? AND status='pending'",
               (approver, now, digest))
    db.commit()
    return load(db, digest)


def post(db, digest, github, now):
    """Post an approved comment once. Repeating a completed request makes no GitHub write."""
    request = load(db, digest)
    if request["status"] == "completed":
        return request
    if request["status"] != "approved":
        raise WriteGateError("the request is not approved")
    action = request["action"]
    if digest_action(action) != digest:
        raise WriteGateError("the stored payload does not match its approved digest")

    repository, number = action["repository"], action["pull_request"]
    pull = github.pull_request(repository, number)
    if pull.get("state") != "open" or pull.get("head_sha") != action["head_sha"]:
        raise WriteGateError("the pull request is closed or its head changed; propose a new comment")

    marker = MARKER.format(digest=digest)
    comment = github.find_comment(repository, number, marker)
    if comment is None:
        comment = github.create_comment(repository, number, f"{action['body']}\n\n{marker}")
    db.execute("""UPDATE write_requests SET status='completed', comment_id=?, comment_url=?, completed_at=?
                  WHERE digest=?""", (comment["id"], comment["url"], now, digest))
    db.commit()
    return load(db, digest)


class GitHubClient:
    """Reads and writes GitHub through the signed-in `gh` command."""

    def _api(self, *args, payload=None):
        try:
            result = subprocess.run(["gh", "api", *args], input=payload, check=True,
                                    capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            raise WriteGateError(f"GitHub request failed: gh api {args[-1]}") from exc
        return json.loads(result.stdout) if result.stdout.strip() else None

    def login(self):
        return self._api("user")["login"]

    def pull_request(self, repository, number):
        pull = self._api(f"repos/{repository}/pulls/{number}")
        return {"state": pull["state"], "head_sha": pull["head"]["sha"]}

    def find_comment(self, repository, number, marker):
        login = self.login()
        pages = self._api("--paginate", "--slurp", f"repos/{repository}/issues/{number}/comments")
        for comment in (item for page in pages for item in page):
            if (comment.get("user") or {}).get("login") == login and marker in (comment.get("body") or ""):
                return {"id": comment["id"], "url": comment["html_url"]}
        return None

    def create_comment(self, repository, number, body):
        comment = self._api("-X", "POST", f"repos/{repository}/issues/{number}/comments", "--input", "-",
                            payload=json.dumps({"body": body}))
        return {"id": comment["id"], "url": comment["html_url"]}


def summary(request):
    action = request["action"]
    return {"digest": request["digest"], "status": request["status"], "repository": action["repository"],
            "pull_request": action["pull_request"], "head_sha": action["head_sha"], "body": action["body"],
            "approver": request["approver"], "comment_url": request["comment_url"]}


def add_arguments(parser):
    parser.add_argument("--db", required=True, type=Path)
    steps = parser.add_subparsers(dest="step", required=True)
    request = steps.add_parser("propose", help="record a pull request comment that needs approval")
    request.add_argument("--repo", required=True)
    request.add_argument("--pr", required=True, type=int)
    request.add_argument("--body-file", required=True, type=Path)
    steps.add_parser("show", help="show a request").add_argument("digest")
    steps.add_parser("approve", help="approve the exact comment with this digest").add_argument("digest")
    steps.add_parser("post", help="post an approved comment once").add_argument("digest")
    return parser


def run_command(args, parser, github=None):
    github = github or GitHubClient()
    args.db.parent.mkdir(parents=True, exist_ok=True)
    lock = args.db.with_suffix(args.db.suffix + ".lock")
    try:
        with exclusive_lock(lock), closing(sqlite3.connect(args.db)) as db:
            init_db(db)
            if args.step == "propose":
                head = github.pull_request(args.repo, args.pr)["head_sha"]
                body = args.body_file.read_text(encoding="utf-8")
                request = propose(db, comment_action(args.repo, args.pr, head, body), utc_timestamp())
            elif args.step == "approve":
                request = approve(db, args.digest, github.login(), utc_timestamp())
            elif args.step == "post":
                request = post(db, args.digest, github, utc_timestamp())
            else:
                request = load(db, args.digest)
    except (WriteGateError, OSError, sqlite3.Error) as exc:
        parser.error(str(exc))
    print(json.dumps(summary(request), indent=2, sort_keys=True))
    return 0
