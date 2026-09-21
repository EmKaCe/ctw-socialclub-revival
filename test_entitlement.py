#!/usr/bin/env python3
"""Conformance and unit tests for ctw_entitlement.

Run with `python3 test_entitlement.py`; no dependencies, exits non-zero on failure. The
vector-driven part reads vectors.json, so a port can be validated against the same data.
"""

import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ctw_entitlement as e  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  PASS  %s" % name)
    else:
        FAIL += 1
        print("  FAIL  %s%s" % (name, ("  -- " + detail) if detail else ""))


def section(title):
    print()
    print("=== %s ===" % title)


def load_vectors():
    with open(os.path.join(ROOT, "vectors.json")) as fh:
        return json.load(fh)


# Vector-driven conformance

def test_decision_vectors(v):
    section("decision vectors (from vectors.json)")
    for case in v["decisions"]:
        pairs = e.parse_gs_pairs(case["upload"])
        spec = case["gate"]
        got_gate, got_why = e.progress_gate_ok(e.save_bytes_from_pairs(pairs), spec)
        keys = list(case["expect"]["keys"].keys())
        got = e.decide(keys, pairs, gate=spec)

        exp = case["expect"]
        check("%s: gate_ok" % case["name"], got_gate == exp["gate_ok"],
              "got %s want %s (%s)" % (got_gate, exp["gate_ok"], got_why))
        check("%s: gate_why" % case["name"], got_why == exp["gate_why"],
              "got %r want %r" % (got_why, exp["gate_why"]))
        check("%s: every key value" % case["name"], got == exp["keys"],
              "differs: %s" % {k: (got.get(k), exp["keys"].get(k))
                               for k in exp["keys"] if got.get(k) != exp["keys"].get(k)})
        check("%s: xin_served" % case["name"],
              bool(got.get(".DLKEY00")) == exp["xin_served"])
        check("%s: sean_served" % case["name"],
              bool(got.get(".DLKEY01")) == exp["sean_served"])


def test_gate_rule_vectors(v):
    section("gate rule vectors (from vectors.json)")
    by_name = {c["name"]: c for c in v["decisions"]}
    for rule in v["gate_rules"]:
        case = by_name[rule["save"]]
        blob = e.save_bytes_from_pairs(e.parse_gs_pairs(case["upload"]))
        got = e.progress_gate_ok(blob, rule["spec"])[0]
        check("rule %-28s -> %s" % (rule["spec"], rule["expect_gate_ok"]),
              got == rule["expect_gate_ok"], "got %s" % got)


def test_reward_predictions(v):
    section("reward word predictions (from vectors.json)")
    for pred in v["reward_word_predictions"]:
        word = e.reward_word_for_keys(pred["keys"])
        check("%s: reward_word" % pred.get("name", "mask 0x%04x" % pred["mask"]),
              word == pred["reward_word"], "got 0x%06x want 0x%06x" % (word, pred["reward_word"]))
        got = list(e.predicted_reward_bytes(pred["mask"]))
        if pred.get("name") == "faithful_complete_with_xin_withheld":
            # that vector is a hypothetical, not a mask product
            check("%s: withheld bytes documented as 05 00 15" % pred["name"],
                  pred["save_bytes_0x6b0"] == [0x05, 0x00, 0x15])
        else:
            check("%s: save bytes" % pred.get("name", "mask 0x%04x" % pred["mask"]),
                  got == pred["save_bytes_0x6b0"], "got %s want %s" % (got, pred["save_bytes_0x6b0"]))


def test_savever_vector(v):
    section("SAVEVER (from vectors.json)")
    sv = v["savever"]
    for case in v["decisions"]:
        if case["name"] != "complete_100pct":
            continue
        pairs = e.parse_gs_pairs(case["upload"])
        got = e.decide(["SAVEVER"], pairs).get("SAVEVER")
        check("SAVEVER echoes the uploaded identity word",
              got == sv["expect_value"], "got %r want %r" % (got, sv["expect_value"]))
        check("SAVEVER is the identity word, not a literal",
              got != "0x021284b9" and got != "34768057")


# Independent checks - properties that must hold regardless of the vectors

def make_save(**kw):
    save = bytearray(e.SAVE_SIZE)
    struct.pack_into("<I", save, 0x00, e.SAVE_MAGIC)
    struct.pack_into("<I", save, e.SAVE_IDENTITY_OFFSET, kw.get("identity", 0x502B76C1))
    struct.pack_into("<I", save, e.STORY_COMPLETE_OFFSET, kw.get("story", 0))
    struct.pack_into("<I", save, e.REACHED_100_OFFSET, kw.get("reached100", 0))
    save[e.LIONS_OFFSET] = kw.get("lions", 0x00)
    for i in range(kw.get("cameras", 0)):
        save[e.CAMERA_BITMAP_OFFSET + (i >> 3)] |= 1 << (i & 7)
    return e.with_fixed_integrity(bytes(save))


def test_properties():
    section("independent properties")

    # blob space vs full-save space must not be confused
    full = make_save(story=50448, lions=2, cameras=100)
    blob = full[e.SAVE_BLOB_BASE:]
    check("blob is shorter than the full save", len(blob) == e.SAVE_SIZE - e.SAVE_BLOB_BASE)
    check("blob_u32 reads a save offset correctly",
          e.blob_u32(blob, e.STORY_COMPLETE_OFFSET) == 50448)
    check("blob_byte reads a save offset correctly", e.blob_byte(blob, e.LIONS_OFFSET) == 2)
    check("blob_bits counts the 100-bit camera run",
          e.blob_bits(blob, e.CAMERA_BITMAP_OFFSET, e.CAMERA_COUNT) == 100)
    check("reading the story field at raw blob offset would be WRONG",
          struct.unpack_from("<I", blob, e.STORY_COMPLETE_OFFSET)[0] != 50448)

    # un-progressed save refused, complete save admitted
    check("early save is refused", e.progress_gate_ok(make_save()[e.SAVE_BLOB_BASE:])[0] is False)
    check("complete save is admitted",
          e.progress_gate_ok(make_save(story=50448, lions=2, cameras=100)[e.SAVE_BLOB_BASE:])[0] is True)

    # story completion alone must not be enough
    story_only = make_save(story=50448, lions=0, cameras=100)[e.SAVE_BLOB_BASE:]
    check("story complete but no Lions is REFUSED (necessary but not sufficient)",
          e.progress_gate_ok(story_only)[0] is False)
    one_lion = make_save(story=50448, lions=1, cameras=100)[e.SAVE_BLOB_BASE:]
    check("story complete with only ONE Lion is REFUSED",
          e.progress_gate_ok(one_lion)[0] is False)

    # no save at all must fail closed
    check("no uploaded save fails closed", e.progress_gate_ok(None)[0] is False)
    check("empty blob fails closed", e.progress_gate_ok(b"")[0] is False)

    # the camera gate is independent of the Xin gate
    no_cams = make_save(story=50448, lions=2, cameras=0)[e.SAVE_BLOB_BASE:]
    check("Xin served with no cameras destroyed", e.progress_gate_ok(no_cams, e.DEFAULT_GATE)[0] is True)
    check("Sean withheld with no cameras destroyed",
          e.progress_gate_ok(no_cams, e.DEFAULT_SEAN_GATE)[0] is False)
    partial = make_save(story=50448, lions=2, cameras=92)[e.SAVE_BLOB_BASE:]
    check("Sean withheld at 92 of 100 cameras",
          e.progress_gate_ok(partial, e.DEFAULT_SEAN_GATE)[0] is False)
    check("Sean served at 100 of 100 cameras",
          e.progress_gate_ok(make_save(cameras=100)[e.SAVE_BLOB_BASE:], e.DEFAULT_SEAN_GATE)[0] is True)

    # .DLKEY00 and .DLKEY01 are gated; the retailer promo vehicles are not
    import base64 as _b64
    pairs_early = {"SAVE": _b64.b64encode(make_save()[e.SAVE_BLOB_BASE:]).decode()}
    d = e.decide([".DLKEY00", ".DLKEY01", ".DLKEY02", ".DLKEY08", ".DLKEY09", ".DLKEY10"], pairs_early)
    check(".DLKEY00 withheld on an early save", d[".DLKEY00"] == "")
    check(".DLKEY01 withheld on an early save", d[".DLKEY01"] == "")
    check("promo vehicles still served on an early save",
          all(d[k] == "1" for k in (".DLKEY02", ".DLKEY08", ".DLKEY09", ".DLKEY10")))
    pairs_done = {"SAVE": _b64.b64encode(make_save(story=50448, lions=2, cameras=100)[e.SAVE_BLOB_BASE:]).decode()}
    d = e.decide([".DLKEY00", ".DLKEY01"], pairs_done)
    check("both gated keys served once their conditions hold",
          d[".DLKEY00"] == "1" and d[".DLKEY01"] == "1")

    # the mask bit for .DLKEYnn is nn, not the reward bit
    check("mask 0x0707 selects DLKEY 0,1,2,8,9,10",
          e.keys_for_mask(0x0707) == [0, 1, 2, 8, 9, 10])
    check("mask bit index differs from reward bit index",
          e.DLKEY_REWARD_BIT[8] == 16 and e.DLKEY_REWARD_BIT[10] == 20)
    check("mask 0x0707 yields the in-game verified bytes 15 00 15",
          e.predicted_reward_bytes(0x0707) == bytes([0x15, 0x00, 0x15]))
    check("faithful-complete with Xin withheld yields 05 00 15",
          bytes([(e.reward_word_for_keys([k for k in e.keys_for_mask(0x0707) if k != 0]) >> (8 * i)) & 0xFF
                 for i in range(3)]) == bytes([0x05, 0x00, 0x15]))

    # keys with no reward bit must not invent one
    check(".DLKEY04 writes nothing", 4 not in e.DLKEY_REWARD_BIT)
    check(".DLKEY11 is not a reward", 11 not in e.DLKEY_REWARD_BIT)

    # integrity
    good = make_save()
    check("synthetic save has a valid integrity field", e.integrity_ok(good))
    bad = bytearray(good)
    bad[0x100] ^= 0xFF
    check("a single flipped byte invalidates the save", not e.integrity_ok(bytes(bad)))
    check("with_fixed_integrity repairs it", e.integrity_ok(e.with_fixed_integrity(bytes(bad))))
    check("integrity needs the full save, and a blob is not one",
          len(blob) < e.SAVE_INTEGRITY_END)

    # malformed input must not crash
    check("undecodable SAVE blob returns None", e.decode_save_blob("!!!not base64!!!") is None)
    check("missing SAVE key returns None", e.save_bytes_from_pairs({"FKEY": "1"}) is None)
    check("empty key list yields no values", e.decide([], {"SAVE": ""}) == {})
    check("unknown keys pass through empty",
          e.decide(["SOMETHING"], {}) == {"SOMETHING": ""})


def main():
    v = load_vectors()
    test_decision_vectors(v)
    test_gate_rule_vectors(v)
    test_reward_predictions(v)
    test_savever_vector(v)
    test_properties()
    print()
    print("%d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
