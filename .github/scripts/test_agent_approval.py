import io
import json
import os
import unittest
import zipfile
from unittest.mock import patch

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
        return gate.evaluate(
            "repos/org/repo", self.pr, self.rules, "app[bot]", self.reviews
        )[0]

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

    def test_only_app_withdrawals_allow_reapproval(self):
        self.reviews.append(dict(review("app[bot]", "DISMISSED", kind="Bot"), id=9))
        event = {
            "event": "review_dismissed",
            "actor": {"login": "maintainer"},
            "dismissed_review": {"review_id": 9},
        }
        with patch.object(
            gate,
            "pages",
            side_effect=lambda path: (
                [event]
                if "/timeline?" in path
                else self.files
                if "/files?" in path
                else []
            ),
        ):
            self.assertFalse(self.allowed())
            event["actor"]["login"] = "app[bot]"
            self.assertTrue(self.allowed())

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
        self.assertEqual(self.assessment.call_count, 1)


class EvidenceTest(unittest.TestCase):
    def test_only_replies_to_current_unedited_assessment_receive_endorsements(self):
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
            if path.endswith(f"/artifacts?name=assessment-1-{run['run_attempt']}"):
                return {"artifacts": [artifact]}
            if payload and path.endswith("/pulls/1/comments"):
                comments.append(
                    {
                        "user": {"login": "app[bot]", "type": "Bot"},
                        "id": len(comments) + 1,
                        "created_at": "now",
                        "updated_at": "now",
                        "original_commit_id": payload["commit_id"],
                        **payload,
                    }
                )
                return comments[-1]
            self.fail(path)

        def read():
            return gate.assessment(
                "repos/org/repo", 1, "head", base, "app[bot]", "README.md", comments
            )

        with (
            patch.object(gate, "api", side_effect=api),
            patch.object(gate, "pages", return_value=comments),
            patch.object(
                gate.subprocess, "check_output", return_value=archive.getvalue()
            ),
        ):
            self.assertEqual(read(), ("low", "none", set()))
            self.assertEqual(comments[0]["subject_type"], "file")
            self.assertEqual(comments[0]["path"], "README.md")
            self.assertIn(
                "`+1` to agree or `-1` to disagree",
                comments[0]["body"].splitlines()[-1],
            )
            vote = {
                "user": {"type": "User", "login": "owner"},
                "id": 2,
                "body": "+1",
                "in_reply_to_id": 42,
                "created_at": "now",
                "updated_at": "now",
            }
            comments.append(vote)
            self.assertEqual(read(), ("low", "none", set()))
            vote["in_reply_to_id"] = comments[0]["id"]
            self.assertEqual(read(), ("low", "none", {"owner"}))
            disagreement = {**vote, "id": 3, "body": "-1\nNeeds a migration"}
            comments.append(disagreement)
            self.assertEqual(read(), ("low", "none", set()))
            comments.remove(disagreement)
            self.assertEqual(read(), ("low", "none", {"owner"}))
            run["run_attempt"] = 3
            self.assertEqual(read(), ("low", "none", set()))
            self.assertEqual(read(), ("low", "none", set()))
            run["run_attempt"] = 2
            vote["body"] = "-1"
            self.assertEqual(read(), ("low", "none", set()))
            vote["body"] = "+1"
            comments[0]["updated_at"] = "later"
            self.assertEqual(read(), ("low", "none", set()))
            self.assertEqual(read(), ("low", "none", set()))
            run["conclusion"] = "failure"
            self.assertIsNone(read())
            run["conclusion"] = "success"
            run["pull_requests"][0]["head"]["sha"] = "old"
            self.assertIsNone(read())

    def test_withdraw_only_bot_approvals(self):
        reviews = [
            dict(review("owner"), id=4),
            dict(review("app[bot]", kind="Bot"), id=5),
            dict(review("app[bot]", "COMMENTED", kind="Bot"), id=6),
        ]
        reviews.append(dict(review("app[bot]", sha="old", kind="Bot"), id=7))
        with patch.object(gate, "api", return_value={"head": {"sha": "head"}}) as api:
            gate.withdraw_approvals(
                "pulls/1", reviews, "app[bot]", "head", False, "Endorsement withdrawn"
            )
            writes = [c for c in api.call_args_list if c.kwargs.get("method") == "PUT"]
            self.assertEqual(
                [(c.args[0], c.kwargs["payload"]["message"]) for c in writes],
                [
                    ("pulls/1/reviews/5/dismissals", "Endorsement withdrawn"),
                    (
                        "pulls/1/reviews/7/dismissals",
                        "A new commit needs fresh review.",
                    ),
                ],
            )
            api.reset_mock()
            gate.withdraw_approvals(
                "pulls/1", reviews, "app[bot]", "head", True, "Endorsed"
            )
            self.assertEqual(
                [c.args[0] for c in api.call_args_list if c.kwargs.get("method")],
                ["pulls/1/reviews/7/dismissals"],
            )
            api.reset_mock()
            api.return_value = {"head": {"sha": "new-head"}}
            gate.withdraw_approvals(
                "pulls/1", reviews, "app[bot]", "head", False, "Waiting"
            )
            api.assert_called_once_with("pulls/1")

    def test_decision_check_is_neutral_idempotent_and_updates_by_app_and_pr(self):
        checks = []
        writes = []

        def api(path, **kwargs):
            if kwargs.get("paginate"):
                return [{"check_runs": checks}]
            payload = kwargs["payload"]
            writes.append((path, payload))
            if kwargs.get("method") == "PATCH":
                checks[-1].update(payload)
            else:
                checks.append({**payload, "id": 7, "app": {"slug": "app"}})

        env = {
            "GITHUB_REPOSITORY": "org/repo",
            "GITHUB_RUN_ID": "11",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SERVER_URL": "https://github.com",
        }
        with patch.dict(os.environ, env), patch.object(gate, "api", side_effect=api):
            args = ("repos/org/repo", 1, "head", "app")
            checks.extend(
                [
                    {"app": {"slug": "other"}, "external_id": "flox-review-pr-1"},
                    {"app": {"slug": "app"}, "external_id": "flox-review-pr-2"},
                ]
            )
            gate.publish(*args, "neutral", "Awaiting approval")
            gate.publish(*args, "neutral", "Awaiting approval")
            gate.publish(*args, "success", "Owner approved")
        self.assertEqual(
            [path for path, _ in writes],
            ["repos/org/repo/check-runs", "repos/org/repo/check-runs/7"],
        )
        self.assertEqual(writes[0][1]["conclusion"], "neutral")
        self.assertEqual(writes[1][1]["conclusion"], "success")
        self.assertEqual(
            writes[1][1]["details_url"],
            "https://github.com/org/repo/actions/runs/11/attempts/1",
        )


if __name__ == "__main__":
    unittest.main()
