from contextlib import closing
import json
import sqlite3
import unittest

from security_runtime import write_gate as gate

REPOSITORY = "kobaltoxid/security-runtime-sandbox"
HEAD = "a" * 40
NOW = "2026-11-23T00:00:00+00:00"


class FakeGitHub:
    def __init__(self, head=HEAD, state="open"):
        self.head, self.state = head, state
        self.comments = []
        self.fail_after_create = False

    def login(self):
        return "reviewer"

    def pull_request(self, repository, number):
        return {"state": self.state, "head_sha": self.head}

    def find_comment(self, repository, number, marker):
        return next((comment for comment in self.comments if marker in comment["body"]), None)

    def create_comment(self, repository, number, body):
        comment = {"id": len(self.comments) + 1, "url": f"https://example.invalid/{len(self.comments) + 1}",
                   "body": body}
        self.comments.append(comment)
        if self.fail_after_create:
            raise gate.WriteGateError("connection lost after the comment was created")
        return comment


class WriteGateTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        gate.init_db(self.db)
        self.github = FakeGitHub()

    def request(self, body="Verdict: evidence supports the report.", pull_request=1):
        return gate.propose(self.db, gate.comment_action(REPOSITORY, pull_request, HEAD, body), NOW)

    def test_comment_waits_for_approval(self):
        request = self.request()
        self.assertEqual(request["status"], "pending")
        with self.assertRaisesRegex(gate.WriteGateError, "not approved"):
            gate.post(self.db, request["digest"], self.github, NOW)
        self.assertEqual(self.github.comments, [])

    def test_approved_comment_is_posted_with_its_digest(self):
        digest = self.request()["digest"]
        self.assertEqual(gate.approve(self.db, digest, "reviewer", NOW)["approver"], "reviewer")
        posted = gate.post(self.db, digest, self.github, NOW)
        self.assertEqual(posted["status"], "completed")
        self.assertEqual(len(self.github.comments), 1)
        self.assertIn(gate.MARKER.format(digest=digest), self.github.comments[0]["body"])

    def test_changed_body_or_destination_needs_a_new_approval(self):
        approved = self.request()["digest"]
        gate.approve(self.db, approved, "reviewer", NOW)
        for changed in (self.request(body="Verdict: edited after approval."), self.request(pull_request=2)):
            with self.subTest(changed=changed["action"]):
                self.assertNotEqual(changed["digest"], approved)
                with self.assertRaisesRegex(gate.WriteGateError, "not approved"):
                    gate.post(self.db, changed["digest"], self.github, NOW)
        self.assertEqual(self.github.comments, [])

    def test_tampered_payload_does_not_match_the_approval(self):
        digest = self.request()["digest"]
        gate.approve(self.db, digest, "reviewer", NOW)
        action = gate.load(self.db, digest)["action"]
        action["body"] = "Something else"
        self.db.execute("UPDATE write_requests SET action_json=? WHERE digest=?", (json.dumps(action), digest))
        with self.assertRaisesRegex(gate.WriteGateError, "does not match"):
            gate.post(self.db, digest, self.github, NOW)

    def test_moved_pull_request_head_blocks_the_write(self):
        digest = self.request()["digest"]
        gate.approve(self.db, digest, "reviewer", NOW)
        self.github.head = "b" * 40
        with self.assertRaisesRegex(gate.WriteGateError, "head changed"):
            gate.post(self.db, digest, self.github, NOW)

    def test_retrying_a_completed_request_leaves_one_comment(self):
        digest = self.request()["digest"]
        gate.approve(self.db, digest, "reviewer", NOW)
        gate.post(self.db, digest, self.github, NOW)
        gate.post(self.db, digest, self.github, NOW)
        self.assertEqual(len(self.github.comments), 1)

    def test_retry_after_an_unrecorded_post_finds_the_existing_comment(self):
        digest = self.request()["digest"]
        gate.approve(self.db, digest, "reviewer", NOW)
        self.github.fail_after_create = True
        with self.assertRaises(gate.WriteGateError):
            gate.post(self.db, digest, self.github, NOW)
        self.assertEqual(gate.load(self.db, digest)["status"], "approved")
        self.github.fail_after_create = False
        self.assertEqual(gate.post(self.db, digest, self.github, NOW)["comment_id"], 1)
        self.assertEqual(len(self.github.comments), 1)

    def test_rejects_invalid_destinations(self):
        for args in (("not-a-repo", 1, HEAD, "x"), (REPOSITORY, 0, HEAD, "x"), (REPOSITORY, 1, "abc", "x"), (REPOSITORY, 1, HEAD, " ")):
            with self.subTest(args=args), self.assertRaises(gate.WriteGateError):
                gate.comment_action(*args)


if __name__ == "__main__":
    unittest.main()
