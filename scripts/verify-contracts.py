"""Verify the synthetic schema examples and reject unbound completion claims."""

from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"


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


if __name__ == "__main__":
    main()
