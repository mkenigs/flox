"""Reconcile main's PRs from the trusted default-branch workflow."""

import functools
import io
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

CONTEXT = "Flox owner review"
POLICY = Path(".github/flox-bot-codeowners")


def api(path, *, payload=None, paginate=False):
    args = ["gh", "api", path]
    if paginate:
        args.extend(["--paginate", "--slurp"])
    if payload is not None:
        args.extend(["--input", "-"])
    result = subprocess.run(
        args,
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True,
        text=True,
        check=True,
    )
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


def assessment(repo, number, head, base, bot):
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
    assessment_ref = f"{run['id']}/{run['run_attempt']}"
    command = f"+1 {assessment_ref}"
    body = (
        f"**Claude risk assessment · {risk}**\n\n{reason}\n\nHighest finding severity: {severity}.\n\n"
        f"To endorse this assessment, post a PR comment containing only `{command}`. "
        f"If you disagree, comment `-1 {assessment_ref}` and explain why.\n\n"
        f"Reviewed {head} · [review run]({run['html_url']}/attempts/{run['run_attempt']})"
    )
    path = f"{repo}/issues/{number}/comments"
    comments = pages(path)
    comment = next(
        (
            c
            for c in comments
            if c["user"]["login"] == bot
            and c["body"] == body
            and c["updated_at"] == c["created_at"]
        ),
        None,
    )
    if not comment:
        api(path, payload={"body": body})
        return risk, severity, set()

    endorsers = {
        c["user"]["login"]
        for c in comments
        if c["user"]["type"] == "User"
        and c["body"].strip() == command
        and c["id"] > comment["id"]
        and c["updated_at"] == c["created_at"]
    }
    return risk, severity, endorsers


def evaluate(repo, pr, rules, bot):
    number = pr["number"]
    head = pr["head"]["sha"]
    author = pr["user"]["login"]
    path = f"{repo}/pulls/{number}"
    if pr["draft"]:
        return False, "Draft pull request"
    files = pages(f"{path}/files?per_page=100")
    if len(files) != pr["changed_files"]:
        return False, "Incomplete file list"
    paths = {f[k] for f in files for k in ("filename", "previous_filename") if k in f}
    groups = coverage(paths, rules)

    def logins(owner):
        if "/" in owner:
            return members(*owner.split("/"))
        return {owner}

    owners = [set().union(*(logins(owner) for owner in group)) for group in groups]
    reviews = pages(f"{path}/reviews?per_page=100")
    approvals, objections = review_votes(reviews, head)
    if all(group & (approvals - {author}) for group in owners):
        return True, "Approved by owners of all changed paths"

    if objections & set.union(*owners):
        return False, "An owner requested changes"
    if (
        pr["head"]["repo"] is None
        or pr["head"]["repo"]["full_name"] != repo.removeprefix("repos/")
        or any(
            p.startswith((".github/", ".agents/", ".claude/"))
            or p.split("/")[-1] == "AGENTS.md"
            for p in paths
        )
    ):
        return False, "Independent owner review required"
    result = assessment(repo, number, head, pr["base"]["sha"], bot)
    if author not in set.intersection(*owners) or result is None:
        return False, "Awaiting independent approval or eligible owner assessment"
    risk, severity, endorsers = result
    if risk != "low" or severity not in ("none", "minor"):
        return False, "Independent owner review required by assessment"
    if not endorsers.intersection(set.union(*owners)):
        return False, "Awaiting an owner's endorsement comment on the risk assessment"
    for finding in pages(f"{path}/comments?per_page=100"):
        if (
            finding["user"]["login"] == "claude[bot]"
            and finding["original_commit_id"] == head
            and not finding.get("in_reply_to_id")
            and not finding["body"].startswith("**Minor**")
        ):
            return False, "Blocking or unclassified inline Claude finding"
    if any(
        r["user"]["login"] == bot
        and r["state"] == "DISMISSED"
        and r["commit_id"] == head
        for r in reviews
    ):
        return False, "Bot approval dismissed; independent owner review required"
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


def publish(repo, sha, bot, allowed, description):
    state = "success" if allowed else "failure"
    statuses = pages(f"{repo}/commits/{sha}/statuses?per_page=100")
    last = next((s for s in statuses if s["context"] == CONTEXT), None)
    if last and (last["creator"]["login"], last["state"], last["description"]) == (
        bot,
        state,
        description,
    ):
        return
    api(
        f"{repo}/statuses/{sha}",
        payload={"state": state, "context": CONTEXT, "description": description},
    )


def open_entries(org, name):
    # Query the queue before evaluating evidence. A subsequent enqueue or push
    # must wait for a new pass on its own speculative commit.
    query = """query($org:String!, $name:String!, $endCursor:String, $withQueue:Boolean!) {
      repository(owner:$org, name:$name) {
        pullRequests(first:100, after:$endCursor, states:OPEN, baseRefName:"main") {
          nodes { number headRefOid mergeQueueEntry @include(if:$withQueue) { headCommit { oid } } }
          pageInfo { hasNextPage endCursor }
        }
      }
    }"""
    variables = {
        "org": org,
        "name": name,
        "withQueue": os.environ["OWNER_TYPE"] == "Organization",
    }
    while True:
        response = api("graphql", payload={"query": query, "variables": variables})
        connection = response["data"]["repository"]["pullRequests"]
        yield from connection["nodes"]
        if not connection["pageInfo"]["hasNextPage"]:
            return
        variables["endCursor"] = connection["pageInfo"]["endCursor"]


def main():
    org, name = os.environ["GITHUB_REPOSITORY"].split("/")
    repo = f"repos/{org}/{name}"
    bot = os.environ["APP_SLUG"] + "[bot]"
    rules = owner_rules(POLICY.read_text(), org)
    decisions = {}
    failed = False
    for entry in list(open_entries(org, name)):
        head = entry["headRefOid"]
        try:
            pr = api(f"{repo}/pulls/{entry['number']}")
            if (
                pr["state"] != "open"
                or pr["head"]["sha"] != head
                or pr["base"]["ref"] != "main"
            ):
                continue
            decision = evaluate(repo, pr, rules, bot)
        except (
            OSError,
            subprocess.CalledProcessError,
            ValueError,
            KeyError,
            TypeError,
            zipfile.BadZipFile,
        ) as error:
            print(f"PR #{entry['number']}: {error}", file=sys.stderr)
            decision = False, "Unable to verify owner review"
            failed = True
        commits = [head]
        queued = entry.get("mergeQueueEntry")
        if queued and queued["headCommit"]:
            commits.append(queued["headCommit"]["oid"])
        for sha in commits:
            if sha not in decisions or not decision[0]:
                decisions[sha] = decision
    for sha, decision in decisions.items():
        try:
            publish(repo, sha, bot, *decision)
        except subprocess.CalledProcessError as error:
            print(f"Could not publish {sha}: {error}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
