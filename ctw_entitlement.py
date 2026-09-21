"""Pure entitlement logic for the GTA: Chinatown Wars (DS) Social Club revival.

Takes bytes, returns bytes: no I/O and no globals, so the decision can be tested and ported on its
own. The transport lives in ctw_selfhost.py.
"""

from __future__ import annotations

import base64
import struct

SAVE_SIZE = 8192
SAVE_MAGIC = 0xA731B56F
SAVE_INTEGRITY_OFFSET = 0x04     # u32le, == sum(save[8:0x2000]) & 0xFFFFFFFF
SAVE_INTEGRITY_START = 0x08
SAVE_INTEGRITY_END = 0x2000
SAVE_IDENTITY_OFFSET = 0x230     # the save's own identity word

SAVE_BLOB_BASE = 0x1EC

# Reward-delivery bytes: three bytes of 2-bit fields, written by the client.
REWARD_BYTES_OFFSET = 0x6B0
REWARD_BYTES_LENGTH = 3

STORY_COMPLETE_OFFSET = 0x3C4    # u32le, seconds of "time to complete story"; 0 = story not finished
REACHED_100_OFFSET = 0x3C0       # u32le, seconds of "time to achieve 100%"; 0 = never reached
LIONS_OFFSET = 0x424             # byte; 2 = both Lions of Fo, matches the game's own stat

# Security cameras: one bit each, 0x684-0x68F plus the low nibble of 0x690. 1 = destroyed.
CAMERA_BITMAP_OFFSET = 0x684
CAMERA_COUNT = 100

# The key suffix is a decimal index selecting a key, not a bit in the reward word.

DLKEY_REWARD_BIT = {
    0: 4,     # .DLKEY00 - Xin Shan missions
    1: 2,     # .DLKEY01 - Sean, the 81st dealer
    2: 0,     # .DLKEY02 - Bulletproof Patriot
    3: 6,     # .DLKEY03 - unidentified (also writes save 0x0DF3)
    5: 10,    # .DLKEY05 - $10,000
    6: 12,    # .DLKEY06 - unidentified
    7: 14,    # .DLKEY07 - unidentified
    8: 16,    # .DLKEY08 - Bulletproof Infernus
    9: 18,    # .DLKEY09 - Bulletproof Hellenbach
    10: 20,   # .DLKEY10 - Bulletproof Cavalcade FXT
}
# .DLKEY04 writes nothing at all. .DLKEY11 is a money clamp, not a reward.

DLKEY_MEANING = {
    0: "Xin Shan missions",
    1: "Sean (81st dealer)",
    2: "Bulletproof Patriot",
    3: "unidentified",
    5: "$10,000",
    6: "unidentified",
    7: "unidentified",
    8: "Bulletproof Infernus",
    9: "Bulletproof Hellenbach",
    10: "Bulletproof Cavalcade FXT",
}

# Reward word as it lands in the save: 0x6B0 carries bits 0-7, 0x6B1 8-15, 0x6B2 16-23.
REWARD_BYTE_COUNT = 3

# Presets, as `--dlkey-mask` values. The mask bit for `.DLKEYnn` is simply `nn`.
MASK_FAITHFUL_COMPLETE = 0x0707   # five promo rewards plus Xin
MASK_FAITHFUL_WITH_MONEY = 0x0727  # as above plus $10,000
MASK_PROMO_ONLY = 0x0706          # five promo rewards, no Xin
MASK_PERMISSIVE = 0x07FF          # every defined slot; the fallback

DEFAULT_GATE = "0x3C4:!=0,0x424:0x02:0x02"
DEFAULT_SEAN_GATE = "0x684:bits:100"



def parse_gs_pairs(message: str) -> dict:
    r"""Parse a GameSpy `\key\value\` message. Empty values produce doubled backslashes."""
    if isinstance(message, bytes):
        message = message.decode("latin-1", "replace")
    t = message.split("\\")
    return {t[i]: t[i + 1] for i in range(1, len(t) - 1, 2)}


def decode_save_blob(blob_b64: str) -> bytes | None:
    r"""Decode the `\SAVE\<base64>` blob into raw save bytes. The console does not always pad."""
    if not blob_b64:
        return None
    try:
        raw = base64.b64decode(blob_b64 + "=" * ((4 - len(blob_b64) % 4) % 4))
    except Exception:  # noqa: BLE001 - a malformed blob is a normal condition, not a crash
        return None
    return raw or None


def save_bytes_from_pairs(pairs: dict) -> bytes | None:
    r"""Pull the uploaded save out of parsed `\\setpd\\` data."""
    return decode_save_blob((pairs or {}).get("SAVE", ""))


# `blob_*` take save offsets and convert; the integrity helpers need a FULL save, because
# the integrity field at 0x04 is not inside the uploaded blob at all.


def blob_u32(blob: bytes, save_offset: int) -> int:
    return struct.unpack_from("<I", blob, save_offset - SAVE_BLOB_BASE)[0]


def blob_byte(blob: bytes, save_offset: int) -> int:
    return blob[save_offset - SAVE_BLOB_BASE]


def blob_bits(blob: bytes, save_offset: int, count: int) -> int:
    """Set bits in a `count`-bit run starting at `save_offset`, lowest bit of the first byte first."""
    base = save_offset - SAVE_BLOB_BASE
    return sum(
        1 for i in range(count) if base + (i >> 3) < len(blob) and (blob[base + (i >> 3)] >> (i & 7)) & 1
    )


def integrity_of(full_save: bytes) -> int:
    """The value the game expects at 0x04: the byte sum of a full save from 8 to 0x2000."""
    return sum(full_save[SAVE_INTEGRITY_START:SAVE_INTEGRITY_END]) & 0xFFFFFFFF


def integrity_ok(full_save: bytes) -> bool:
    if len(full_save) < SAVE_SIZE:
        return False
    return blob_u32_full(full_save, SAVE_INTEGRITY_OFFSET) == integrity_of(full_save)


def blob_u32_full(full_save: bytes, offset: int) -> int:
    return struct.unpack_from("<I", full_save, offset)[0]


def with_fixed_integrity(full_save: bytes) -> bytes:
    """Return a full save with a correct integrity field. Only needed when editing saves by hand."""
    out = bytearray(full_save)
    struct.pack_into("<I", out, SAVE_INTEGRITY_OFFSET, integrity_of(bytes(out)))
    return bytes(out)


def progress_gate_ok(blob: bytes | None, spec: str = DEFAULT_GATE) -> tuple[bool, str]:
    """Should this save be served? Returns (ok, reason for the log).

        The client checks no prerequisite of its own, so the original requirement is enforced here.
        The default is the chain the game was played in: story complete AND both Lions of Fo found.

        Rules are comma-separated and all must hold, against save offsets: `0x3C4:!=0`, `0x3C4:==50448`,
        `0x424:0x02:0x02` (byte AND value), `0x684:bits:100` (set bits in a run). `off` always serves.
        """
    if not spec or str(spec).strip().lower() == "off":
        return True, "gate off"
    if blob is None:
        return False, "no uploaded save to check"

    for rule in str(spec).split(","):
        rule = rule.strip()
        if not rule:
            continue
        parts = rule.split(":")
        try:
            off = int(parts[0], 0)
        except ValueError:
            return True, "unparsable rule %r - allowing" % rule

        blob_off = off - SAVE_BLOB_BASE

        if len(parts) == 2 and parts[1][:2] in ("!=", "=="):
            if blob_off < 0 or blob_off + 4 > len(blob):
                return False, "save offset 0x%x outside the uploaded blob" % off
            got = struct.unpack_from("<I", blob, blob_off)[0]
            try:
                want = int(parts[1][2:], 0)
            except ValueError:
                return True, "unparsable rule %r - allowing" % rule
            if parts[1][0] == "!" and got == want:
                return False, "save[0x%x] = %d, must differ from %d" % (off, got, want)
            if parts[1][0] == "=" and got != want:
                return False, "save[0x%x] = %d, need %d" % (off, got, want)

        elif len(parts) == 3 and parts[1].strip().lower() == "bits":
            try:
                want = int(parts[2], 0)
            except ValueError:
                return True, "unparsable rule %r - allowing" % rule
            if blob_off < 0 or blob_off + (CAMERA_COUNT + 7) // 8 > len(blob):
                return False, "save offset 0x%x outside the uploaded blob" % off
            got = blob_bits(blob, off, CAMERA_COUNT)
            if got != want:
                return False, "save[0x%x] has %d of %d bits set, need %d" % (
                    off, got, CAMERA_COUNT, want)

        elif len(parts) == 3:
            try:
                mask, val = int(parts[1], 0), int(parts[2], 0)
            except ValueError:
                return True, "unparsable rule %r - allowing" % rule
            if blob_off < 0 or blob_off >= len(blob):
                return False, "save offset 0x%x outside the uploaded blob" % off
            got = blob[blob_off] & mask
            if got != val:
                return False, "save[0x%x]&0x%x = 0x%x, need 0x%x" % (off, mask, got, val)

        else:
            return True, "unparsable rule %r - allowing" % rule

    return True, "passed"


def story_complete(blob: bytes) -> bool:
    return blob_u32(blob, STORY_COMPLETE_OFFSET) != 0


def reached_100_percent(blob: bytes) -> bool:
    """Has the player ever reached 100%? Not a safe gate: a 100% save reads 0 here."""
    return blob_u32(blob, REACHED_100_OFFSET) != 0


def both_lions_found(blob: bytes) -> bool:
    return blob_byte(blob, LIONS_OFFSET) == 2


def cameras_destroyed(blob: bytes) -> int:
    return blob_bits(blob, CAMERA_BITMAP_OFFSET, CAMERA_COUNT)


def all_cameras_destroyed(blob: bytes) -> bool:
    return cameras_destroyed(blob) == CAMERA_COUNT



def reward_word_for_keys(keys: list[int]) -> int:
    word = 0
    for k in keys:
        bit = DLKEY_REWARD_BIT.get(k)
        if bit is not None:
            word |= 1 << bit
    return word


def keys_for_mask(mask: int) -> list[int]:
    return [k for k in sorted(DLKEY_REWARD_BIT) if (mask >> k) & 1]


def predicted_reward_bytes(mask: int) -> bytes:
    """The reward bytes at save 0x6B0 that a mask should produce, for predicting a round."""
    word = reward_word_for_keys(keys_for_mask(mask))
    return bytes((word >> (8 * i)) & 0xFF for i in range(REWARD_BYTE_COUNT))



def savever_from_save(blob: bytes | None) -> str:
    """The value to serve for `.SAVEVER`: the save's own identity word, never a literal.

        The reward writer only commits a bit when `[0x021f10cc + 0x70]` matches `[profile + 0x2d0]`.
        """
    if blob is None or len(blob) < (SAVE_IDENTITY_OFFSET - SAVE_BLOB_BASE) + 4:
        return ""
    return str(struct.unpack_from("<I", blob, SAVE_IDENTITY_OFFSET - SAVE_BLOB_BASE)[0])


def decide(
    keys: list[str],
    stored_pairs: dict,
    *,
    dlkey_mask: int = MASK_FAITHFUL_COMPLETE,
    dlkey_value: str = "1",
    gate: str = DEFAULT_GATE,
    sean_gate: str = DEFAULT_SEAN_GATE,
    savever_echo: bool = True,
) -> dict:
    """Which value does each requested key get?

        Xin (`.DLKEY00`) is gated on the story and the Lions, Sean (`.DLKEY01`) on the cameras. The
        promo vehicles were retailer codes with no in-game prerequisite, so they are served as asked.
        """
    blob = save_bytes_from_pairs(stored_pairs)
    gate_ok, _ = progress_gate_ok(blob, gate)
    sean_ok, _ = progress_gate_ok(blob, sean_gate)

    out: dict[str, str] = {}
    for k in keys:
        if not k:
            continue
        v = stored_pairs.get(k, "")

        if k == "SAVEVER":
            if savever_echo:
                v = savever_from_save(blob)
            out[k] = v
            continue

        name = k.lstrip(".")
        if name.startswith("DLKEY") and name[5:].isdigit():
            idx = int(name[5:])
            if (dlkey_mask >> idx) & 1:
                if idx == 0:
                    v = dlkey_value if gate_ok else ""
                elif idx == 1:
                    v = dlkey_value if sean_ok else ""
                else:
                    v = dlkey_value
            out[k] = v
            continue

        out[k] = v

    return out


def gate_reason_for_log(blob: bytes | None, spec: str = DEFAULT_GATE) -> tuple[bool, str]:
    """The gate decision plus its reason, for logging both outcomes."""
    return progress_gate_ok(blob, spec)
