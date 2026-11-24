"""Verify the synthetic schema examples and reject unbound completion claims."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import string

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"
ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def read_json(path):
    return json.loads((CONTRACTS / path).read_text(encoding="utf-8"))


def validator(path):
    schema = read_json(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker(formats=["date-time"]))


def verify(trace, event_validator, receipt_validator):
    events = {}
    for event in trace["events"]:
        event_validator.validate(event)
        event_id = event["event"]
        if event_id in events:
            raise ValueError("duplicate event")
        if "parent" in event:
            parent = events.get(event["parent"])
            if parent is None or parent["request"] != event["request"]:
                raise ValueError("missing or mismatched parent")
            for key in ("playthrough", "actor", "utterance"):
                if key in parent and parent[key] != event.get(key):
                    raise ValueError(f"parent has different {key}")
        events[event_id] = event

    for receipt in trace["receipts"]:
        receipt_validator.validate(receipt)
        if receipt["state"] != "completed":
            continue
        evidence = events.get(receipt["evidence"]["event"])
        producer = {"playback": "playback", "engine": "native"}[receipt["evidence"]["source"]]
        if evidence is None or evidence["producer"] != producer or evidence["kind"] != "completed":
            raise ValueError("receipt lacks attributable completion evidence")
        for key in ("request", "actor", "playthrough", "utterance"):
            if receipt.get(key) != evidence.get(key):
                raise ValueError(f"receipt has different {key}")


class Refusal(ValueError):
    """A typed identity-v1 refusal. The reason string is part of the contract."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def lower(text):
    """ASCII case folding only: the engine's plugin and editor-ID comparison."""
    return text.translate(ASCII_LOWER)


def form_key(form):
    if form["origin"] == "dynamic":
        return f"dynamic|{form['runtime_form_id']}"
    return f"{lower(form['plugin']['file'])}|{form['local_form_id']}"


def actor_key(playthrough, reference, epoch):
    incarnation = reference.get("incarnation")
    if reference["origin"] == "plugin":
        scoped = form_key(reference) + (f"#{incarnation}" if incarnation else "")
    elif incarnation:
        scoped = f"dynamic|{incarnation}"
    else:
        scoped = f"dynamic|{epoch['session']}.{epoch['load_generation']}.{reference['runtime_form_id']}"
    return f"actor:{playthrough}:{scoped}"


def opaque_actor(key):
    """The actor identifier for event-v1 and receipt-v1, which carry no plugin names."""
    return "a-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:40]


class IdentityWorld:
    """Admitted identity records in arrival order, and the resolver over them."""

    def __init__(self, data, schema):
        for records in data.values():
            for record in records:
                schema.validate(record)

        self.playthroughs = {}
        for record in data["playthroughs"]:
            name = record.get("name")
            derived = {
                hashlib.new(algorithm, text.encode("utf-8")).hexdigest()[:32]
                for algorithm in ("md5", "sha1", "sha256")
                for text in ((name, name.strip(), lower(name.strip())) if name else ())
            }
            if record["id"] in derived:
                raise Refusal("playthrough-derived-from-name")
            if record["id"] in self.playthroughs:
                raise Refusal("duplicate-playthrough")
            self.playthroughs[record["id"]] = record

        self.orders = {}
        for record in data["load_orders"]:
            plugins = {lower(plugin["file"]): plugin for plugin in record["plugins"]}
            indexes = {plugin["load_index"] for plugin in record["plugins"]}
            if record["session"] in self.orders or not len(plugins) == len(indexes) == len(record["plugins"]):
                raise Refusal("load-order-conflict")
            self.orders[record["session"]] = plugins

        self.saves = {}
        for record in data["saves"]:
            self.playthrough(record)
            if record["id"] in self.saves:
                raise Refusal("duplicate-save")
            if record["parent"] is not None:
                self.saved(record["parent"], record["playthrough"])
            self.saves[record["id"]] = record

        self.epochs = {}
        self.generation = {}
        self.current = None
        for record in data["loads"]:
            self.playthrough(record)
            session, generation = record["session"], record["load_generation"]
            if generation <= self.generation.get(session, 0):
                raise Refusal("load-generation-not-monotonic")
            if record["save"] is not None:
                self.saved(record["save"], record["playthrough"])
            self.generation[session] = generation
            self.epochs[session, generation] = record["playthrough"]
            self.current = record
        for record in self.saves.values():
            self.loaded(record, record["playthrough"])

        self.actors = {}
        for record in data["actors"]:
            self.playthrough(record)
            reference, base, epoch = record["reference"], record["base"], record.get("observed")
            if epoch:
                self.loaded(epoch, record["playthrough"])
                self.runtime(reference, epoch["session"])
                self.runtime(base, epoch["session"])
            portable = reference["origin"] == base["origin"] == "plugin" and "incarnation" not in reference
            if record["portable"] != portable:
                raise Refusal("portable-flag-mismatch")
            key = actor_key(record["playthrough"], reference, epoch)
            if key in self.actors:
                raise Refusal("duplicate-actor")
            self.actors[key] = record

        self.quests = {}
        for record in data["quests"]:
            key = "quest:" + form_key(record["form"])
            if key in self.quests:
                raise Refusal("duplicate-quest")
            self.quests[key] = record

        self.events = {}
        for record in data["events"]:
            self.loaded(record, record["playthrough"])
            key = f"event:{record['session']}:{record['sequence']}"
            if key in self.events:
                if self.events[key] != record:
                    raise Refusal("event-id-conflict")
                continue  # an exact replay changes nothing
            # Arrival order is free. Within a session, load generations may not run against the sequence.
            for other in self.events.values():
                if other["session"] != record["session"]:
                    continue
                earlier, later = sorted((other, record), key=lambda event: event["sequence"])
                if earlier["load_generation"] > later["load_generation"]:
                    raise Refusal("event-order-violation")
            if "subject" in record:
                self.owned(record["subject"], record["playthrough"])
            self.events[key] = record

    def playthrough(self, record):
        if record["playthrough"] not in self.playthroughs:
            raise Refusal("unknown-playthrough")

    def saved(self, save, playthrough):
        if save not in self.saves:
            raise Refusal("unknown-save")
        if self.saves[save]["playthrough"] != playthrough:
            raise Refusal("cross-playthrough")

    def loaded(self, epoch, playthrough):
        owner = self.epochs.get((epoch["session"], epoch["load_generation"]))
        if owner is None:
            raise Refusal("unknown-load-generation")
        if owner != playthrough:
            raise Refusal("cross-playthrough")

    def owned(self, key, playthrough):
        actor = self.actors.get(key)
        if actor is None:
            raise Refusal("unknown-actor")
        if actor["playthrough"] != playthrough:
            raise Refusal("cross-playthrough")
        return actor

    def runtime(self, form, session):
        """A stated runtime form ID must be the one this session's load order produces."""
        if form["origin"] != "plugin" or "runtime_form_id" not in form:
            return
        if session not in self.orders:
            raise Refusal("unknown-load-order")
        plugin = self.orders[session].get(lower(form["plugin"]["file"]))
        if plugin is None:
            raise Refusal("unknown-plugin")
        if plugin["kind"] != form["plugin"]["kind"]:
            raise Refusal("plugin-kind-mismatch")
        local = form["local_form_id"]
        if plugin["load_index"] + (local[3:] if plugin["kind"] == "light" else local) != form["runtime_form_id"]:
            raise Refusal("runtime-form-id-mismatch")

    def resolve(self, request):
        """Exactly one identity, or a typed refusal. A name never overrides an identity."""
        playthrough = self.current["playthrough"]
        if request["playthrough"] != playthrough:
            raise Refusal("cross-playthrough")
        epoch = {"session": request["session"], "load_generation": request["load_generation"]}
        if epoch["session"] != self.current["session"]:
            raise Refusal("stale-session" if epoch["session"] in self.generation else "unknown-session")
        if epoch["load_generation"] != self.current["load_generation"]:
            stale = epoch["load_generation"] < self.current["load_generation"]
            raise Refusal("stale-load-generation" if stale else "unknown-load-generation")

        target = request["target"]
        if target["by"] == "quest":
            self.runtime(target["form"], epoch["session"])
            key = "quest:" + form_key(target["form"])
            if key not in self.quests:
                raise Refusal("unknown-quest")
            if lower(self.quests[key]["editor_id"]) != lower(target["editor_id"]):
                raise Refusal("quest-editor-id-mismatch")
            return key
        if target["by"] == "key":
            actor = self.owned(target["key"], playthrough)
            reference = actor["reference"]
            if reference["origin"] == "dynamic" and "incarnation" not in reference and actor["observed"] != epoch:
                raise Refusal("dynamic-reference-stale")
            return target["key"]
        if target["by"] == "name":
            wanted = lower(target["name"].strip())
            named = {
                actor_key(playthrough, candidate["reference"], epoch): candidate
                for candidate in request["candidates"]
                if lower(candidate["name"].strip()) == wanted
            }
            if not named:
                raise Refusal("unknown-name")
            if len(named) > 1:
                raise Refusal("ambiguous-name")
            target = next(iter(named.values()))

        reference, base = target["reference"], target["base"]
        self.runtime(reference, epoch["session"])
        self.runtime(base, epoch["session"])
        key = actor_key(playthrough, reference, epoch)
        actor = self.actors.get(key)
        if actor is None:
            # Never matched by a recycled dynamic form ID, by base or by name.
            if reference["origin"] == "dynamic" and "incarnation" not in reference and any(
                other["playthrough"] == playthrough and other["reference"]["origin"] == "dynamic"
                and other["reference"]["runtime_form_id"] == reference["runtime_form_id"]
                for other in self.actors.values()
            ):
                raise Refusal("dynamic-reference-stale")
            raise Refusal("unknown-actor")
        if reference["origin"] == "dynamic" and reference["runtime_form_id"] != actor["reference"]["runtime_form_id"]:
            raise Refusal("incarnation-conflict")
        if form_key(base) != form_key(actor["base"]):
            raise Refusal("base-mismatch")
        return key

    def bind(self, trace):
        """Optional identity-v1 keys in the unchanged event-v1 identifier fields."""
        playthroughs = {f"p-{key}": key for key in self.playthroughs}
        actors = {opaque_actor(key): actor for key, actor in self.actors.items()}
        events = {f"e-{event['session']}-{event['sequence']}": event for event in self.events.values()}
        for event in trace["events"]:
            if event.get("playthrough") not in playthroughs:
                raise Refusal("unknown-playthrough")
            playthrough = playthroughs[event["playthrough"]]
            if "actor" in event:
                if event["actor"] not in actors:
                    raise Refusal("unknown-actor")
                if actors[event["actor"]]["playthrough"] != playthrough:
                    raise Refusal("cross-playthrough")
            if event["producer"] == "native":
                if event["event"] not in events:
                    raise Refusal("unknown-event")
                if events[event["event"]]["playthrough"] != playthrough:
                    raise Refusal("cross-playthrough")


def verify_identity(event_validator, receipt_validator):
    schema = validator("identity-v1.schema.json")
    fixture = read_json("fixtures/identity.json")
    world = IdentityWorld(fixture["world"], schema)

    outcomes = {"resolved": 0, "refusal": 0}
    for case in fixture["cases"]:
        schema.validate(case["request"])
        try:
            outcome = {"resolved": world.resolve(case["request"])}
        except Refusal as refusal:
            outcome = {"refusal": refusal.reason}
        if outcome != case["expect"]:
            raise ValueError(f"identity case {case['name']!r}: {outcome}")
        outcomes[next(iter(outcome))] += 1

    for case in fixture["invalid"]:
        errors = {("/".join(map(str, error.absolute_path)), error.validator)
                  for error in schema.iter_errors(case["record"])}
        if errors != {(case["at"], case["keyword"])}:
            raise ValueError(f"invalid identity record {case['name']!r}: {sorted(errors)}")

    def refused(name, reason, action):
        try:
            action()
        except Refusal as refusal:
            if refusal.reason == reason:
                return
            raise ValueError(f"{name!r} refused as {refusal.reason}, expected {reason}") from refusal
        raise ValueError(f"accepted invalid identity case: {name}")

    for case in fixture["world_invalid"]:
        data = deepcopy(fixture["world"])
        data[case["collection"]].append(case["record"])
        refused(case["name"], case["reason"], lambda: IdentityWorld(data, schema))

    trace = fixture["trace"]
    verify(trace, event_validator, receipt_validator)
    world.bind(trace)
    for case in fixture["trace_invalid"]:
        edited = deepcopy(trace)
        edited["events"][case["event"]][case["field"]] = case["value"]
        event_validator.validate(edited["events"][case["event"]])
        refused(case["name"], case["reason"], lambda: world.bind(edited))

    rejected = len(fixture["invalid"]) + len(fixture["world_invalid"]) + len(fixture["trace_invalid"])
    print(f"PASS: identity resolution, {outcomes['resolved']} resolved, {outcomes['refusal']} typed refusals, "
          f"{rejected} rejected records")


def main():
    event_validator = validator("event-v1.schema.json")
    receipt_validator = validator("receipt-v1.schema.json")
    trace = read_json("fixtures/trace.json")
    verify(trace, event_validator, receipt_validator)

    def invalid_case(name, edit):
        case = deepcopy(trace)
        edit(case)
        try:
            verify(case, event_validator, receipt_validator)
        except (ValidationError, ValueError):
            return
        raise ValueError(f"accepted invalid trace: {name}")

    invalid_case("private payload", lambda t: t["events"][0].update(transcript="synthetic"))
    invalid_case("unknown version", lambda t: t["events"][0].update(version=2))
    invalid_case("invalid event time", lambda t: t["events"][0].update(occurred_at="yesterday"))
    invalid_case("duplicate", lambda t: t["events"].insert(1, t["events"][0]))
    invalid_case("missing parent", lambda t: t["events"][1].update(parent="missing"))
    invalid_case("wrong playthrough", lambda t: t["events"][2].update(playthrough="play-2"))
    invalid_case("missing playback evidence", lambda t: t["receipts"][0].pop("evidence"))
    invalid_case("inferred completion", lambda t: t["receipts"][0]["evidence"].update(event="infer-a"))
    invalid_case("different actor", lambda t: t["receipts"][0].update(actor="actor-2"))
    invalid_case("wrong utterance", lambda t: t["receipts"][0].update(utterance="line-2"))

    action = {"version": 1, "kind": "world-action", "request": "r",
              "actor": "a", "playthrough": "p", "state": "completed",
              "evidence": {"event": "e", "source": "engine"}}
    event = {"version": 1, "event": "e", "request": "r", "producer": "native",
             "actor": "a", "playthrough": "p", "kind": "completed",
             "occurred_at": "2026-11-23T11:00:00Z"}
    verify({"events": [event], "receipts": [action]}, event_validator, receipt_validator)
    print("PASS: speech and action correlation, 10 rejection cases")
    verify_admission()
    verify_identity(event_validator, receipt_validator)


def verify_admission():
    """Check installer admission receipts and reject ones that claim more than they show."""
    admission = validator("admission-receipt-v1.schema.json")
    receipts = read_json("fixtures/admission-receipts.json")

    def check(receipt):
        admission.validate(receipt)
        if receipt["decision"] != "refused" and any(
                archive["approved_sha256"] != archive.get("observed_sha256")
                for archive in receipt["archives"]):
            raise ValueError("admitted bytes differ from the approved digest")

    for receipt in receipts.values():
        check(receipt)

    cases = {
        "download location": ("admitted", lambda r: r["archives"][0].update(url="https://example.invalid/a?key=1")),
        "archive path": ("admitted", lambda r: r["archives"][0].update(file_name="downloads/a.7z")),
        "unknown version": ("admitted", lambda r: r.update(version=2)),
        "admitted without a plan": ("admitted", lambda r: r.pop("plan")),
        "admitted without activation": ("admitted", lambda r: r.pop("activation")),
        "admitted without observed bytes": ("admitted", lambda r: r["archives"][0].pop("observed_sha256")),
        "admitted other bytes": ("admitted", lambda r: r["archives"][0].update(observed_sha256="5" * 64)),
        "admitted with a refusal": ("admitted", lambda r: r.update(refusal={"code": "error", "detail": "x"})),
        "allowed disguised executable": ("admitted", lambda r: r["allowed_executables"].append("disguised")),
        "executable as an extra type": ("admitted", lambda r: r["allowed_extra_types"].append("EXE")),
        "refused without a reason": ("refused", lambda r: r.pop("refusal")),
        "refused yet activated": ("refused", lambda r: r.update(activation={"method": "rename", "replaced_existing": False})),
        "unknown refusal code": ("refused", lambda r: r["refusal"].update(code="ignored")),
        "missing limit": ("refused", lambda r: r["limits"].pop("max_entries")),
    }
    for name, (base, edit) in cases.items():
        case = deepcopy(receipts[base])
        edit(case)
        try:
            check(case)
        except (ValidationError, ValueError):
            continue
        raise ValueError(f"accepted invalid admission receipt: {name}")
    print(f"PASS: admission receipts, {len(cases)} rejection cases")


if __name__ == "__main__":
    main()
