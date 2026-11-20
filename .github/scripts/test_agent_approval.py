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

    def test_renames_existing_endorsement_check_without_replacing_its_log(self):
        job = "https://github.com/org/repo/actions/runs/11/job/101"
        reason = gate.AWAITING_ENDORSEMENT
        check = {
            "id": 7,
            "external_id": "flox-review-pr-1",
            "app": {"slug": "app"},
            "name": "Flox agent review decision",
            "conclusion": "neutral",
            "details_url": job,
            "output": {
                "title": "Awaiting owner approval",
                "summary": f"PR #1 at `head`\n\n{reason}\n\n[Open the decision job log]({job})",
            },
        }
        with patch.object(
            gate, "api", side_effect=[[{"check_runs": [check]}], {}]
        ) as api:
            gate.publish("repos/org/repo", 1, "head", "app", "neutral", reason)
        self.assertNotIn("check_name=", api.call_args_list[0].args[0])
        self.assertEqual(api.call_args.args, ("repos/org/repo/check-runs/7",))
        self.assertEqual(api.call_args.kwargs["method"], "PATCH")
        self.assertEqual(
            api.call_args.kwargs["payload"],
            {
                "name": "flox-review[bot] decision",
                "status": "completed",
                "conclusion": "neutral",
                "output": {
                    **check["output"],
                    "title": "Awaiting author risk endorsement",
                },
                "details_url": job,
            },
        )

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

        first_job = "https://github.com/org/repo/actions/runs/11/job/101"
        next_job = "https://github.com/org/repo/actions/runs/11/job/102"
        with (
            patch.dict(os.environ, DECISION_JOB_URL=first_job),
            patch.object(gate, "api", side_effect=api),
        ):
            args = ("repos/org/repo", 1, "head", "app")
            checks.extend(
                [
                    {"app": {"slug": "other"}, "external_id": "flox-review-pr-1"},
                    {"app": {"slug": "app"}, "external_id": "flox-review-pr-2"},
                ]
            )
            gate.publish(*args, "neutral", "Awaiting approval")
            os.environ["DECISION_JOB_URL"] = next_job
            gate.publish(*args, "neutral", "Awaiting approval")
            gate.publish(*args, "success", "Owner approved")
        self.assertEqual(
            [path for path, _ in writes],
            ["repos/org/repo/check-runs", "repos/org/repo/check-runs/7"],
        )
        self.assertEqual(writes[0][1]["conclusion"], "neutral")
        self.assertEqual(writes[0][1]["output"]["title"], "Awaiting owner approval")
        self.assertEqual(writes[1][1]["conclusion"], "success")
        for (_, payload), job in zip(writes, (first_job, next_job), strict=True):
            self.assertEqual(payload["details_url"], job)
            self.assertIn(
                f"[Open the decision job log]({job})", payload["output"]["summary"]
            )

        # Existing checks from before job links were added are updated in place.
        checks[-1]["output"]["summary"] = "PR #1 at `head`\n\nOwner approved"
        checks[-1]["details_url"] = (
            "https://github.com/org/repo/actions/runs/11/attempts/1"
        )
        with (
            patch.dict(os.environ, DECISION_JOB_URL=next_job),
            patch.object(gate, "api", side_effect=api),
        ):
            gate.publish(*args, "success", "Owner approved")
        self.assertEqual(writes[-1][0], "repos/org/repo/check-runs/7")
        self.assertEqual(checks[-1]["details_url"], next_job)


if __name__ == "__main__":
    unittest.main()
