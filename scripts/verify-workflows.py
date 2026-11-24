"""Assert the hosted workflow trust boundary and the required check context."""

import argparse
from copy import deepcopy
import json
from pathlib import Path
import re

import yaml

PINNED = re.compile(r"[0-9a-f]{40}")
JOB_KEYS = {"name", "runs-on", "timeout-minutes", "env", "steps"}
STEP_KEYS = {"name", "uses", "with", "run", "env"}


def strings(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from strings(key)
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)
    elif isinstance(node, str):
        yield node


def check_workflow(name, workflow, policy):
    """Return every violation of the policy in one parsed workflow."""
    errors = []
    # YAML 1.1 reads the bare key `on` as the boolean true.
    events = workflow.get("on", workflow.get(True))
    if events != policy["events"]:
        errors.append(f"{name}: events differ from the reviewed set")
    if workflow.get("permissions") != policy["permissions"]:
        errors.append(f"{name}: workflow permissions differ from the reviewed set")
    for text in strings(workflow):
        if re.search(r"\bsecrets\b|github\.token|GITHUB_TOKEN", text):
            errors.append(f"{name}: references a credential")
            break
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return errors + [f"{name}: no jobs"]
    for job_id, job in jobs.items():
        where = f"{name}: job {job_id}"
        if not isinstance(job, dict):
            errors.append(f"{where} is not a mapping")
            continue
        extra = set(job) - JOB_KEYS
        if extra:
            errors.append(f"{where} uses unreviewed keys {sorted(map(str, extra))}")
        if job.get("runs-on") not in policy["runners"]:
            errors.append(f"{where} does not run on a reviewed hosted runner")
        if not isinstance(job.get("timeout-minutes"), int):
            errors.append(f"{where} has no bounded time")
        for index, step in enumerate(job.get("steps") or [], 1):
            at = f"{where} step {index}"
            if not isinstance(step, dict) or set(step) - STEP_KEYS:
                errors.append(f"{at} uses unreviewed keys")
                continue
            if "${{" in str(step.get("run", "")):
                errors.append(f"{at} interpolates an expression into a script")
            uses = step.get("uses")
            if uses is None:
                continue
            action, _, ref = str(uses).partition("@")
            if not PINNED.fullmatch(ref) or policy["actions"].get(action) != ref:
                errors.append(f"{at} uses an action outside the reviewed full-commit pins")
            if action != "actions/checkout":
                continue
            options = step.get("with") or {}
            if options.get("persist-credentials") is not False:
                errors.append(f"{at} persists the checkout credential")
            repository = options.get("repository")
            if repository is not None:
                ref = str(options.get("ref", ""))
                if not PINNED.fullmatch(ref) or policy.get("repositories", {}).get(repository) != ref:
                    errors.append(f"{at} reads another repository outside its reviewed commit")
    return errors


def check(workflows, policy):
    errors = []
    for name, workflow in sorted(workflows.items()):
        if not isinstance(workflow, dict):
            errors.append(f"{name}: not a mapping")
            continue
        errors.extend(check_workflow(name, workflow, policy))
    required = policy["required_check"]
    producers = [name for name, workflow in workflows.items() if isinstance(workflow, dict)
                 for job in (workflow.get("jobs") or {}).values()
                 if isinstance(job, dict) and job.get("name") == required["context"]]
    if len(producers) != 1 or workflows[producers[0]].get("name") != required["workflow"]:
        errors.append("required check context is not produced by exactly one job "
                      "of its named workflow")
    return errors


def load(root):
    policy = json.loads((root / ".github/workflow-policy.json").read_text(encoding="utf-8"))
    if policy.get("version") != 1:
        raise ValueError("unknown workflow policy version")
    directory = root / ".github/workflows"
    paths = sorted(p for p in directory.iterdir() if p.suffix in {".yml", ".yaml"})
    return {p.name: yaml.safe_load(p.read_text(encoding="utf-8")) for p in paths}, policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        workflows, policy = load(args.root.resolve())
        errors = check(workflows, policy)
        if errors:
            raise ValueError("\n".join(errors))
    except (OSError, ValueError, KeyError, yaml.YAMLError) as error:
        parser.exit(1, f"{error}\n")

    required = policy["required_check"]
    owner = next(name for name, workflow in workflows.items()
                 if workflow.get("name") == required["workflow"])
    job = next(job_id for job_id, job in workflows[owner]["jobs"].items()
               if job.get("name") == required["context"])

    def first_step(workflow):
        return workflow["jobs"][job]["steps"][0]

    def on(workflow):
        return workflow["on" if "on" in workflow else True]

    step = "uses an action outside the reviewed full-commit pins"
    cases = {
        "privileged trigger": ("events differ", lambda w: on(w).update(pull_request_target=None)),
        "path filter": ("events differ",
                        lambda w: on(w).update(pull_request={"paths": ["src/**"]})),
        "write permission": ("permissions differ",
                             lambda w: w["permissions"].update(contents="write")),
        "job permission": ("unreviewed keys ['permissions']",
                           lambda w: w["jobs"][job].update(permissions={"contents": "write"})),
        "renamed required job": ("required check context",
                                 lambda w: w["jobs"][job].update(name="Renamed")),
        "conditional required job": ("unreviewed keys ['if']",
                                     lambda w: w["jobs"][job].update(**{"if": "false"})),
        "tolerated failure": ("unreviewed keys ['continue-on-error']",
                              lambda w: w["jobs"][job].update(**{"continue-on-error": True})),
        "matrix context": ("unreviewed keys ['strategy']",
                           lambda w: w["jobs"][job].update(strategy={"matrix": {"a": [1]}})),
        "self-hosted runner": ("reviewed hosted runner",
                               lambda w: w["jobs"][job].update(**{"runs-on": "self-hosted"})),
        "unbounded job": ("no bounded time", lambda w: w["jobs"][job].pop("timeout-minutes")),
        "deployment environment": ("unreviewed keys ['environment']",
                                   lambda w: w["jobs"][job].update(environment="release")),
        "tag pin": (step, lambda w: first_step(w).update(uses="actions/checkout@v4")),
        "unreviewed commit": (step, lambda w: first_step(w).update(
            uses="actions/checkout@" + "0" * 40)),
        "unreviewed action": (step, lambda w: w["jobs"][job]["steps"].append(
            {"uses": "actions/cache@" + "0" * 40})),
        "persisted credential": ("persists the checkout credential",
                                 lambda w: first_step(w)["with"].pop("persist-credentials")),
        "secret reference": ("references a credential", lambda w: w["jobs"][job]["steps"].append(
            {"run": "true", "env": {"TOKEN": "${{ secrets.TOKEN }}"}})),
        "script interpolation": ("interpolates an expression", lambda w: w["jobs"][job][
            "steps"].append({"run": "echo ${{ github.event.pull_request.title }}"})),
        "tolerated step failure": ("unreviewed keys", lambda w: w["jobs"][job]["steps"].append(
            {"run": "false", "continue-on-error": True})),
        "unpinned repository": ("another repository outside its reviewed commit",
                                lambda w: w["jobs"][job]["steps"].append(
                                    {"uses": first_step(w)["uses"],
                                     "with": {"repository": "example/other", "ref": "main",
                                              "persist-credentials": False}})),
        "duplicate required context": ("required check context", None),
    }
    for name, (expected, edit) in cases.items():
        case = deepcopy(workflows)
        if edit is None:
            case["second.yml"] = deepcopy(workflows[owner])
        else:
            edit(case[owner])
        found = check(case, policy)
        if len(found) != 1 or expected not in found[0]:
            parser.exit(1, f"invalid workflow not rejected for its reason: {name}: {found}\n")
    print(f"PASS: {len(workflows)} workflow, required context "
          f"\"{required['context']}\", {len(cases)} rejection cases")


if __name__ == "__main__":
    main()
