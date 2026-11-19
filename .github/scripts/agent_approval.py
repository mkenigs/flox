"""Reconcile main's PRs from the trusted default-branch workflow."""

import functools
import io
import json
import os
import re
import subprocess
import sys
import urllib.parse
import zipfile
from pathlib import Path

CHECK_NAME = "Flox agent review decision"
POLICY = Path(".github/flox-bot-codeowners")


def api(path, *, payload=None, paginate=False, method=None):
    args = ["gh", "api", path]
    if method:
        args.extend(["--method", method])
    if paginate:
        args.extend(["--paginate", "--slurp"])
    if payload is not None:
        args.extend(["--input", "-"])
    result = subprocess.run(
        args,
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        print(result.stderr.rstrip(), file=sys.stderr)
        result.check_returncode()
    return json.loads(result.stdout)


def pages(path):
    return [item for page in api(path, paginate=True) for item in page]


def owner_rules(contents, org):
    rules = []
    for line in contents.splitlines():
        fields = line.partition("#")[0].split()
        if not fields:
            continue
        pattern, *owners = fields
        if pattern != "*" and not re.fullmatch(r"/[\w./-]+/", pattern):
            raise ValueError(f"Unsupported ownership pattern {pattern}")
        if not owners or not all(
            re.fullmatch(rf"@(?:{re.escape(org)}/[\w-]+|[A-Za-z0-9-]+)", o)
            for o in owners
        ):
            raise ValueError(f"Expected users or repository teams for {pattern}")
        rules.append((pattern, frozenset(o.removeprefix("@") for o in owners)))
    return rules


def coverage(paths, rules):
    required = set()
    for path in paths:
        for pattern, teams in reversed(rules):
            if pattern == "*" or path.startswith(pattern[1:]):
                required.add(teams)
                break
        else:
            raise ValueError(f"No owners for {path!r}")
    if not required:
        raise ValueError("Empty file list")
    return required


@functools.cache
def members(org, team):
    return {
        u["login"]
        for u in pages(f"orgs/{org}/teams/{team}/members?per_page=100")
        if u["type"] == "User"
    }


def review_votes(reviews, head):
    # COMMENTED reviews leave an existing vote in effect.
    latest = {}
    for review in reviews:
        if review["user"]["type"] == "User" and review["state"] in {
            "APPROVED",
            "CHANGES_REQUESTED",
            "DISMISSED",
        }:
            latest[review["user"]["login"]] = review
    return (
        {
            login
            for login, r in latest.items()
            if r["state"] == "APPROVED" and r["commit_id"] == head
        },
        {login for login, r in latest.items() if r["state"] == "CHANGES_REQUESTED"},
    )


def assessment(repo, number, head, base, bot, anchor, comments):
    runs = api(
        f"{repo}/actions/workflows/claude-review.yml/runs"
        f"?head_sha={head}&event=pull_request&per_page=100"
    )
    run = next(
        (
            r
            for r in runs["workflow_runs"]
            if any(
                p["number"] == number
                and p["head"]["sha"] == head
                and p["base"]["ref"] == "main"
                for p in r["pull_requests"]
            )
        ),
        None,
    )
    if not run or run["conclusion"] != "success":
        return None
    name = f"assessment-{number}-{run['run_attempt']}"
    artifacts = api(f"{repo}/actions/runs/{run['id']}/artifacts?name={name}")[
        "artifacts"
    ]
    if len(artifacts) != 1 or artifacts[0]["expired"]:
        return None
    artifact = artifacts[0]
    if artifact["size_in_bytes"] > 32768:
        raise ValueError("Oversize assessment")
    archive = subprocess.check_output(
        ["gh", "api", f"{repo}/actions/artifacts/{artifact['id']}/zip"]
    )
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        info = z.getinfo("assessment.json")
        if info.file_size > 16384:
            raise ValueError("Oversize assessment JSON")
        result = json.loads(z.read(info))
    original_base = result["base"]
    if not re.fullmatch("[0-9a-f]{40}", original_base):
        raise ValueError("Invalid assessment base")
    if original_base != base:

        def merge_base(ref):
            return api(f"{repo}/compare/{ref}...{head}?per_page=1")[
                "merge_base_commit"
            ]["sha"]

        if merge_base(original_base) != merge_base(base):
            return None

    risk, severity, reason = (
        result[k] for k in ("risk", "highest_severity", "rationale")
    )
    if (
        risk not in ("low", "medium", "high")
        or severity not in ("none", "minor", "important", "critical")
        or not isinstance(reason, str)
        or not 0 < len(reason.strip()) <= 2000
    ):
        raise ValueError("Invalid assessment")
    body = (
        f"**Claude risk assessment · {risk}**\n\n{reason}\n\nHighest finding severity: {severity}.\n\n"
        f"Reviewed {head} · [review run {run['id']}, attempt {run['run_attempt']}]"
        f"({run['html_url']}/attempts/{run['run_attempt']})\n\n"
        "You can add your reasoning on the second line.\n\n"
        "Reply in this thread with `+1` to agree or `-1` to disagree."
    )
    root = next(
        (
            c
            for c in comments
            if c["user"]["login"] == bot
            and not c.get("in_reply_to_id")
            and c["original_commit_id"] == head
            and c["body"] == body
            and c["created_at"] == c["updated_at"]
        ),
        None,
    )
    if root is None:
        api(
            f"{repo}/pulls/{number}/comments",
            payload={
                "commit_id": head,
                "path": anchor,
                "subject_type": "file",
                "body": body,
            },
        )
        return risk, severity, set()

    votes = {}
    for reply in sorted(comments, key=lambda c: c["id"]):
        if reply.get("in_reply_to_id") != root["id"] or reply["user"]["type"] != "User":
            continue
        lines = reply["body"].strip().splitlines()
        if lines and lines[0].strip() in ("+1", "-1"):
            votes[reply["user"]["login"]] = lines[0].strip()
    return risk, severity, {login for login, vote in votes.items() if vote == "+1"}


def evaluate(repo, pr, rules, bot, reviews):
    number = pr["number"]
    head = pr["head"]["sha"]
    author = pr["user"]["login"]
    path = f"{repo}/pulls/{number}"
    if pr["draft"]:
        return False, "Draft pull request"
    files = pages(f"{path}/files?per_page=100")
    if len(files) != pr["changed_files"]:
        raise ValueError("Incomplete changed file list")
    paths = {f[k] for f in files for k in ("filename", "previous_filename") if k in f}
    groups = coverage(paths, rules)

    def logins(owner):
        if "/" in owner:
            return members(*owner.split("/"))
        return {owner}

    owners = [set().union(*(logins(owner) for owner in group)) for group in groups]
    same_repo = (pr["head"]["repo"] or {}).get("full_name") == repo.removeprefix(
        "repos/"
    )
    result = None
    comments = []
    if same_repo:
        comments = pages(f"{path}/comments?per_page=100")
        # GitHub review threads need a diff anchor, even for a PR-wide assessment.
        anchor = next(
            (f["filename"] for f in files if f.get("status") != "removed"),
            files[0]["filename"],
        )
        result = assessment(
            repo, number, head, pr["base"]["sha"], bot, anchor, comments
        )

    approvals, objections = review_votes(reviews, head)
    print(
        f"PR #{number}: owner groups {sorted(sorted(group) for group in groups)}, "
        f"current human approvals {sorted(approvals)}, owner objections {sorted(objections & set.union(*owners))}"
    )
    if result is not None:
        risk, severity, endorsers = result
        print(
            f"PR #{number}: risk {risk}, highest finding {severity}, endorsements {sorted(endorsers)}"
        )
    if all(group & (approvals - {author}) for group in owners):
        return True, "Independent owners approved all changed paths"
    if objections & set.union(*owners):
        return False, "An owner requested changes"
    if not same_repo:
        return False, "Independent owner review required for a fork PR"
    protected = sorted(
        p
        for p in paths
        if p.startswith((".github/", ".agents/", ".claude/"))
        or p.split("/")[-1] == "AGENTS.md"
    )
    if protected:
        return False, f"Independent owner review required for `{protected[0]}`"
    if author not in set.intersection(*owners):
        return (
            False,
            "Independent owner review required because the author does not own every changed path",
        )
    if result is None:
        return False, "Awaiting a completed Claude assessment for the current changes"
    risk, severity, endorsers = result
    if risk != "low" or severity not in ("none", "minor"):
        return (
            False,
            f"Independent owner review required (risk: {risk}, highest finding: {severity})",
        )
    if not endorsers.intersection(set.union(*owners)):
        return False, "Awaiting an owner's +1 reply in the risk assessment thread"
    for finding in comments:
        if (
            finding["user"]["login"] == "claude[bot]"
            and finding["original_commit_id"] == head
            and not finding.get("in_reply_to_id")
            and not finding["body"].startswith("**Minor**")
        ):
            return False, "Blocking or unclassified inline Claude finding"
    dismissed = {
        str(r["id"])
        for r in reviews
        if r["user"]["login"] == bot
        and r["state"] == "DISMISSED"
        and r["commit_id"] == head
    }
    if dismissed:
        # The app can restore its own withdrawn approval after a fresh endorsement.
        withdrawn = {
            str(event["dismissed_review"]["review_id"])
            for event in pages(f"{repo}/issues/{number}/timeline?per_page=100")
            if event["event"] == "review_dismissed"
            and (event.get("actor") or {}).get("login") == bot
        }
        if dismissed - withdrawn:
            return (
                False,
                "Bot approval dismissed by a reviewer; independent owner review required",
            )
    if not any(
        r["user"]["login"] == bot
        and r["state"] == "APPROVED"
        and r["commit_id"] == head
        for r in reviews
    ):
        api(
            f"{path}/reviews",
            payload={
                "commit_id": head,
                "event": "APPROVE",
                "body": "Owner-authored change with an endorsed low-risk assessment.",
            },
        )
    return True, "Owner-authored, low risk and endorsed"


def withdraw_approvals(path, reviews, bot, head, allowed, reason):
    for review in reviews:
        if review["user"]["login"] != bot or review["state"] != "APPROVED":
            continue
        if review["commit_id"] == head and allowed:
            continue
        # A push can race reconciliation. Leave the new head to its own run.
        if api(path)["head"]["sha"] != head:
            return
        message = (
            reason
            if review["commit_id"] == head
            else "A new commit needs fresh review."
        )
        api(
            f"{path}/reviews/{review['id']}/dismissals",
            method="PUT",
            payload={"message": message},
        )


def publish(repo, number, head, slug, conclusion, reason):
    external_id = f"flox-review-pr-{number}"
    url = f"{repo}/commits/{head}/check-runs?check_name={urllib.parse.quote(CHECK_NAME)}&filter=all&per_page=100"
    existing = next(
        (
            check
            for page in api(url, paginate=True)
            for check in page["check_runs"]
            if check["app"]["slug"] == slug and check["external_id"] == external_id
        ),
        None,
    )

    def summary(job_url):
        return f"PR #{number} at `{head}`\n\n{reason}\n\n[Open the decision job log]({job_url})"

    # Keep the link to the job that established this decision on repeated runs.
    if (
        existing
        and existing["conclusion"] == conclusion
        and existing["output"]["summary"] == summary(existing["details_url"])
    ):
        return
    job_url = os.environ["DECISION_JOB_URL"]
    payload = {
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": {
                "neutral": "Awaiting owner approval",
                "success": "Owner review satisfied",
                "failure": "Unable to evaluate owner review",
            }[conclusion],
            "summary": summary(job_url),
        },
        "details_url": job_url,
    }
    if existing:
        api(f"{repo}/check-runs/{existing['id']}", method="PATCH", payload=payload)
    else:
        api(
            f"{repo}/check-runs",
            payload={
                **payload,
                "name": CHECK_NAME,
                "head_sha": head,
                "external_id": external_id,
            },
        )


def main():
    org, name = os.environ["GITHUB_REPOSITORY"].split("/")
    repo = f"repos/{org}/{name}"
    slug = os.environ["APP_SLUG"]
    bot = slug + "[bot]"
    rules = owner_rules(POLICY.read_text(), org)
    failed = False
    for entry in pages(f"{repo}/pulls?state=open&base=main&per_page=100"):
        number, head = entry["number"], entry["head"]["sha"]
        path = f"{repo}/pulls/{number}"
        reviews = None
        try:
            pr = api(path)
            if (
                pr["state"] != "open"
                or pr["head"]["sha"] != head
                or pr["base"]["ref"] != "main"
            ):
                continue
            reviews = pages(f"{path}/reviews?per_page=100")
            allowed, reason = evaluate(repo, pr, rules, bot, reviews)
            conclusion = "success" if allowed else "neutral"
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            subprocess.CalledProcessError,
            zipfile.BadZipFile,
        ) as error:
            print(f"PR #{number}: {error}", file=sys.stderr)
            reason = f"Could not verify approval ({type(error).__name__}). See the reconciliation log."
            conclusion = "failure"
            failed = True
        try:
            if reviews is None:
                reviews = pages(f"{path}/reviews?per_page=100")
            withdraw_approvals(
                path, reviews, bot, head, conclusion == "success", reason
            )
        except subprocess.CalledProcessError as error:
            print(f"PR #{number}: {error}", file=sys.stderr)
            conclusion, reason = (
                "failure",
                "Could not withdraw the bot approval. See the reconciliation log.",
            )
            failed = True
        print(f"PR #{number} {head}: {conclusion} — {reason}")
        try:
            publish(repo, number, head, slug, conclusion, reason)
        except subprocess.CalledProcessError as error:
            print(f"Could not publish check for PR #{number}: {error}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
