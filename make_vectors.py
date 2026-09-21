#!/usr/bin/env python3
"""Generate vectors.json - the cross-language conformance vectors.

A port is only trustworthy if it can be checked against something, so these are synthetic saves
and the exact decision each must produce. No third-party save is redistributed; the offsets and
values are the real ones.

Usage:  python3 make_vectors.py            # rewrites vectors.json
"""

import base64
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ctw_entitlement as e  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")

KEYS = [".DLKEY00", ".DLKEY01", ".DLKEY02", ".DLKEY03", ".DLKEY04", ".DLKEY05", ".DLKEY06",
        ".DLKEY07", ".DLKEY08", ".DLKEY09", ".DLKEY10", ".DLKEY11", ".DLKEY12", ".DLKEY13",
        ".DLKEY14", ".DLKEY15", "FKEY", "SAVEVER"]


def make_save(*, identity=0x502B76C1, story=0, reached100=0, lions=0x00, cameras=0, reward=None):
    """Build a synthetic 8192-byte save with a valid integrity field."""
    save = bytearray(e.SAVE_SIZE)
    struct.pack_into("<I", save, 0x00, e.SAVE_MAGIC)
    struct.pack_into("<I", save, e.SAVE_IDENTITY_OFFSET, identity)
    struct.pack_into("<I", save, e.STORY_COMPLETE_OFFSET, story)
    struct.pack_into("<I", save, e.REACHED_100_OFFSET, reached100)
    save[e.LIONS_OFFSET] = lions
    for i in range(cameras):
        save[e.CAMERA_BITMAP_OFFSET + (i >> 3)] |= 1 << (i & 7)
    if reward:
        save[e.REWARD_BYTES_OFFSET:e.REWARD_BYTES_OFFSET + len(reward)] = reward
    return e.with_fixed_integrity(bytes(save))


def as_upload(full_save, fkey="253403395100"):
    r"""Turn a full save into the `\\setpd\\` data the console would send."""
    blob = base64.b64encode(full_save[e.SAVE_BLOB_BASE:]).decode()
    return "\\FKEY\\%s\\NAME\\bQBlAGwAbwBuAEQAUwAAAAAAAAAAAA==\\SAVE\\%s" % (fkey, blob)


SAVE_CASES = [
    # name, save kwargs, gate spec, expected: does .DLKEY00 (Xin) get served?
    ("early_post_yu_jian", dict(story=0, lions=0, cameras=0), None, False),
    ("story_complete_lions_not_collected", dict(story=50448, lions=0, cameras=100), None, False),
    ("one_lion_collected", dict(story=50448, lions=1, cameras=100), None, False),
    ("lions_collected_story_not_complete", dict(story=0, lions=2, cameras=0), None, False),
    ("complete_100pct", dict(story=50448, lions=2, cameras=100), None, True),
    ("complete_gate_off", dict(story=50448, lions=2, cameras=100), "off", True),
    ("early_gate_off", dict(story=0, lions=0, cameras=0), "off", True),
]

GATE_CASES = [
    ("off", True),
    ("0x3C4:!=0", True),
    ("0x3C4:==50448", True),
    ("0x3C4:==1", False),
    ("0x424:0x02:0x02", True),
    ("0x424:0x01:0x01", False),      # 0x02 & 0x01 == 0x00
    ("0x684:bits:100", True),
    ("0x684:bits:99", False),
    ("0x3C4:!=0,0x424:0x02:0x02", True),
    ("0x3C4:!=0,0x424:0x04:0x04", False),
    ("nonsense", True),            # unparsable rules ALLOW and say so
]


def build():
    vectors = {
        "format": 1,
        "note": "Conformance vectors for the GTA: Chinatown Wars (DS) Social entitlement decision. "
                "Saves are synthetic; offsets and values are real.",
        "constants": {
            "SAVE_SIZE": e.SAVE_SIZE,
            "SAVE_BLOB_BASE": e.SAVE_BLOB_BASE,
            "SAVE_IDENTITY_OFFSET": e.SAVE_IDENTITY_OFFSET,
            "STORY_COMPLETE_OFFSET": e.STORY_COMPLETE_OFFSET,
            "LIONS_OFFSET": e.LIONS_OFFSET,
            "CAMERA_BITMAP_OFFSET": e.CAMERA_BITMAP_OFFSET,
            "CAMERA_COUNT": e.CAMERA_COUNT,
            "REWARD_BYTES_OFFSET": e.REWARD_BYTES_OFFSET,
            "DEFAULT_GATE": e.DEFAULT_GATE,
            "DEFAULT_SEAN_GATE": e.DEFAULT_SEAN_GATE,
        },
        "dlkey_reward_bit": {str(k): v for k, v in sorted(e.DLKEY_REWARD_BIT.items())},
        "decisions": [],
        "reward_word_predictions": [],
        "gate_rules": [],
    }

    for name, kwargs, gate, expect in SAVE_CASES:
        full = make_save(**kwargs)
        upload = as_upload(full)
        pairs = e.parse_gs_pairs(upload)
        spec = gate if gate is not None else e.DEFAULT_GATE
        got, why = e.progress_gate_ok(e.save_bytes_from_pairs(pairs), spec)
        decided = e.decide(KEYS, pairs, gate=spec)
        served = bool(decided.get(".DLKEY00"))
        assert served == expect, "%s: got %s expected %s" % (name, served, expect)
        assert got == expect or spec == "off", "%s: gate %s" % (name, got)
        vectors["decisions"].append({
            "name": name,
            "save_fields": {"story": kwargs.get("story", 0),
                            "lions_0x424": kwargs.get("lions", 0x00),
                            "cameras": kwargs.get("cameras", 0)},
            "gate": spec,
            "upload": upload,
            "expect": {
                "gate_ok": got,
                "gate_why": why,
                "keys": decided,
                "xin_served": served,
                "sean_served": bool(decided.get(".DLKEY01")),
            },
        })

    for mask in sorted({e.MASK_FAITHFUL_COMPLETE, e.MASK_PROMO_ONLY,
                        e.MASK_FAITHFUL_WITH_MONEY, e.MASK_PERMISSIVE}):
        vectors["reward_word_predictions"].append({
            "mask": mask,
            "keys": e.keys_for_mask(mask),
            "reward_word": e.reward_word_for_keys(e.keys_for_mask(mask)),
            "save_bytes_0x6b0": list(e.predicted_reward_bytes(mask)),
        })
    # the faithful mask with Xin withheld
    withheld_keys = [k for k in e.keys_for_mask(e.MASK_FAITHFUL_COMPLETE) if k != 0]
    vectors["reward_word_predictions"].append({
        "mask": e.MASK_FAITHFUL_COMPLETE,
        "name": "faithful_complete_with_xin_withheld",
        "keys": withheld_keys,
        "reward_word": e.reward_word_for_keys(withheld_keys),
        "save_bytes_0x6b0": [0x05, 0x00, 0x15],
    })

    full100 = make_save(story=50448, lions=2, cameras=100)
    blob100 = full100[e.SAVE_BLOB_BASE:]
    for spec, expect in GATE_CASES:
        got = e.progress_gate_ok(blob100, spec)[0]
        assert got == expect, "gate rule %r: got %s expected %s" % (spec, got, expect)
        vectors["gate_rules"].append({"save": "complete_100pct", "spec": spec, "expect_gate_ok": got})

    vectors["savever"] = {
        "note": "The client only commits reward bits when [0x021f10cc+0x70] == [profile+0x2d0]. "
                "The correct value to serve is the identity word the client itself uploaded.",
        "identity_word": 0x502B76C1,
        "expect_value": str(0x502B76C1),
    }
    return vectors


if __name__ == "__main__":
    v = build()
    with open(OUT, "w") as fh:
        json.dump(v, fh, indent=2, sort_keys=False)
        fh.write("\n")
    print("wrote %s" % OUT)
    print("  %d decision vectors, %d reward predictions, %d gate rules" % (
        len(v["decisions"]), len(v["reward_word_predictions"]), len(v["gate_rules"])))
