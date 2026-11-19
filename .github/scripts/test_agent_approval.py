import io
import json
import os
import unittest
import zipfile
from unittest.mock import call, patch

import agent_approval as gate


def review(login, state="APPROVED", sha="head", kind="User"):
    return {"user": {"login": login, "type": kind}, "state": state, "commit_id": sha}


class ApprovalTest(unittest.TestCase):
    def setUp(self):
        self.rules = gate.owner_rules("* @org/general\n/schema/ @org/schema", "org")
        self.pr = {
            "number": 1,
            "head": {"sha": "head", "repo": {"full_name": "org/repo"}},
            "base": {"sha": "base"},
            "user": {"login": "author"},
            "draft": False,
            "changed_files": 1,
        }
        self.files = [{"filename": "cli/file"}]
        self.reviews = []
        self.findings = []
        self.endorsers = {"author"}
        responses = {
            "files": self.files,
            "reviews": self.reviews,
            "comments": self.findings,
        }
        self.start_patch(
            "pages",
            side_effect=lambda path: responses[path.split("/")[-1].split("?")[0]],
        )
        self.start_patch(
            "members",
            side_effect=lambda org, team: {
                "general": {"author", "maintainer"},
                "schema": {"schema-owner"},
            }[team],
        )
        self.assessment = self.start_patch(
            "assessment", return_value=("low", "minor", self.endorsers)
        )
        self.api = self.start_patch("api")

    def start_patch(self, name, **kwargs):
        patcher = patch.object(gate, name, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def allowed(self):
        return gate.evaluate("repos/org/repo", self.pr, self.rules, "app[bot]")[0]

    def test_rename_needs_owners_on_both_sides(self):
        self.files[0]["previous_filename"] = "schema/file"
        self.reviews.extend([review("maintainer"), review("schema-owner", sha="old")])
        self.assertFalse(self.allowed())
        self.reviews.extend(
            [review("schema-owner"), review("schema-owner", "COMMENTED")]
        )
        self.assertTrue(self.allowed())
        self.reviews.append(review("schema-owner", "DISMISSED"))
        self.assertFalse(self.allowed())
        self.api.assert_not_called()

    def test_personal_owner_can_endorse_without_team_access(self):
        self.rules = gate.owner_rules("* @author", "author")
        with patch.object(
            gate, "members", side_effect=AssertionError("unexpected team lookup")
        ):
            self.assertTrue(self.allowed())

    def test_endorsed_low_risk_approves_current_head_once(self):
        self.assertTrue(self.allowed())
        self.assertEqual(self.api.call_args.kwargs["payload"]["commit_id"], "head")
        self.reviews.append(review("app[bot]", kind="Bot"))
        self.assertTrue(self.allowed())
        self.api.assert_called_once()
        self.endorsers.clear()
        self.assertFalse(self.allowed())

    def test_blockers_override_endorsement(self):
        for risk, severity in [
            ("low", "important"),
            ("low", "critical"),
            ("medium", "none"),
            ("high", "none"),
        ]:
            with self.subTest(risk=risk, severity=severity):
                self.assessment.return_value = risk, severity, self.endorsers
                self.assertFalse(self.allowed())
        self.assessment.return_value = "low", "minor", self.endorsers
        self.findings.append(
            {
                "user": {"login": "claude[bot]"},
                "original_commit_id": "head",
                "body": "**Critical**",
            }
        )
        self.assertFalse(self.allowed())
        self.findings.clear()
        self.reviews.append(review("maintainer", "CHANGES_REQUESTED"))
        self.assertFalse(self.allowed())
        self.reviews.clear()
        self.endorsers.clear()
        self.endorsers.add("visitor")
        self.assertFalse(self.allowed())
        self.api.assert_not_called()

    def test_policy_edits_and_forks_need_independent_review(self):
        self.files[0]["filename"] = ".github/flox-bot-codeowners"
        self.assertFalse(self.allowed())
        self.files[0]["filename"] = "cli/file"
        self.pr["head"]["repo"]["full_name"] = "fork/repo"
        self.assertFalse(self.allowed())
        self.reviews.extend([review("author"), review("app[bot]", kind="Bot")])
        self.assertFalse(self.allowed())
        self.reviews.append(review("maintainer"))
        self.assertTrue(self.allowed())
        self.assessment.assert_not_called()


class EvidenceTest(unittest.TestCase):
    def test_only_current_run_and_unedited_app_assessment_receive_endorsements(self):
        base = "a" * 40
        result = {
            "risk": "low",
            "rationale": "Formatting only",
            "highest_severity": "none",
            "base": base,
        }
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("assessment.json", json.dumps(result))
        run = {
            "id": 7,
            "run_attempt": 2,
            "conclusion": "success",
            "html_url": "url",
            "pull_requests": [
                {"number": 1, "head": {"sha": "head"}, "base": {"ref": "main"}}
            ],
        }
        artifact = {"id": 3, "expired": False, "size_in_bytes": len(archive.getvalue())}
        comments = []

        def api(path, *, payload=None):
            if "workflows/" in path:
                return {"workflow_runs": [run]}
            if path.endswith("/artifacts?name=assessment-1-2"):
                return {"artifacts": [artifact]}
            if payload and path.endswith("/issues/1/comments"):
                comments.append(
                    {
                        "user": {"login": "app[bot]", "type": "Bot"},
                        "id": len(comments) + 1,
                        "created_at": "now",
                        "updated_at": "now",
                        **payload,
                    }
                )
                return comments[-1]
            self.fail(path)

        def read():
            return gate.assessment("repos/org/repo", 1, "head", base, "app[bot]")

        with (
            patch.object(gate, "api", side_effect=api),
            patch.object(gate, "pages", return_value=comments),
            patch.object(
                gate.subprocess, "check_output", return_value=archive.getvalue()
            ),
        ):
            self.assertEqual(read(), ("low", "none", set()))
            self.assertIn("`+1 7/2`", comments[0]["body"])
            vote = {
                "user": {"type": "User", "login": "owner"},
                "id": 2,
                "body": "+1 7/1",
                "created_at": "now",
                "updated_at": "now",
            }
            comments.append(vote)
            self.assertEqual(read(), ("low", "none", set()))
            vote["body"] = "+1 7/2"
            self.assertEqual(read(), ("low", "none", {"owner"}))
            vote["updated_at"] = "later"
            self.assertEqual(read(), ("low", "none", set()))
            vote["updated_at"] = "now"
            comments[0]["updated_at"] = "later"
            self.assertEqual(read(), ("low", "none", set()))
            self.assertEqual(read(), ("low", "none", set()))
            run["conclusion"] = "failure"
            self.assertIsNone(read())
            run["conclusion"] = "success"
            run["pull_requests"][0]["head"]["sha"] = "old"
            self.assertIsNone(read())

    def test_shared_head_requires_all_prs_and_queue_uses_its_own_commit(self):
        entries = [
            {"number": 1, "headRefOid": "head", "mergeQueueEntry": None},
            {
                "number": 2,
                "headRefOid": "head",
                "mergeQueueEntry": {"headCommit": {"oid": "queue"}},
            },
        ]
        pr = {"state": "open", "head": {"sha": "head"}, "base": {"ref": "main"}}
        env = {"GITHUB_REPOSITORY": "flox/flox", "APP_SLUG": "app"}
        with (
            patch.dict(os.environ, env),
            patch.object(gate, "open_entries", return_value=entries),
            patch.object(gate, "api", return_value=pr),
            patch.object(
                gate, "evaluate", side_effect=[(False, "blocked"), (True, "approved")]
            ),
            patch.object(gate, "publish") as publish,
        ):
            self.assertEqual(gate.main(), 0)
            self.assertEqual(
                publish.call_args_list,
                [
                    call("repos/flox/flox", "head", "app[bot]", False, "blocked"),
                    call("repos/flox/flox", "queue", "app[bot]", True, "approved"),
                ],
            )


if __name__ == "__main__":
    unittest.main()
