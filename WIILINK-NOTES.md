# Notes for a WiiLink contributor

CTW `gamestats`, the logic is in [`ctw_entitlement.py`](../ctw_entitlement.py).

## What the client asks for

`\getpd\` with a `keys` list: `FKEY` and `DLKEY00` … `DLKEY15`. The reply must contain only those keys, with a value each.

**The client checks no prerequisite itself**, the check if both Lions have been collected was entirely server-sided.
I have added the option to enable/disable this check to the script.

## What to write

`.DLKEYnn`'s suffix is a **decimal index 0–15 selecting a key, not a bit**. Each key maps to a bit in
the 24-bit reward word at `0x6B0`. `.DLKEY00` (Xin) is gated on the story and the Lions, `.DLKEY01`
(Sean) on the cameras; the rest are retailer promotions with no in-game prerequisite.

| key | reward bit | save byte | grants |
|---|---|---|---|
| `.DLKEY00` | 4 | `0x6B0` f2 | Xin Shan missions |
| `.DLKEY01` | 2 | `0x6B0` f1 | Sean (81st dealer) 
| `.DLKEY02` | 0 | `0x6B0` f0 | Bulletproof Patriot |
| `.DLKEY03` | 6 | `0x6B0` f3 | unidentified — also writes `0x0DF3` |
| `.DLKEY04` | — | — | empty branch, writes nothing |
| `.DLKEY05` | 10 | `0x6B1` f1 | $10,000 |
| `.DLKEY06` | 12 | `0x6B1` f2 | unidentified |
| `.DLKEY07` | 14 | `0x6B1` f3 | unidentified |
| `.DLKEY08` | 16 | `0x6B2` f0 | Bulletproof Infernus |
| `.DLKEY09` | 18 | `0x6B2` f1 | Bulletproof Hellenbach |
| `.DLKEY10` | 20 | `0x6B2` f2 | Bulletproof Cavalcade FXT |
| `.DLKEY11` | — | — | money clamp, not a reward |

**`.SAVEVER` must echo the client's own upload**.
The reward writer only commits a bit when `[0x021f10cc+0x70] == [profile+0x2d0]`, and `[0x021f113c]` equals `save[0x230]`.
A literal closes the gate and nothing is written.

## The save fields

The upload arrives as `\SAVE\<base64>`, which is the raw save **from offset `0x1EC`**, so convert save offsets before indexing, or you will read plausible garbage.

| offset | meaning |
|---|---|
| `0x230` | identity word / the `.SAVEVER` value |
| `0x3C4` | u32, "time to complete story" in seconds; 0 = story not finished |
| `0x424` | byte, Lions of Fo collected; 2 = both |
| `0x684` | 100 bits, one per security camera (`0x684`–`0x68F` plus the low nibble of `0x690`); 1 = destroyed |

The gate requires **both**: story complete *and* both Lions. Sean (`.DLKEY01`) additionally needs all
100 cameras. Every field was confirmed against the game's own Stats screen, not inferred.

## Verifying a port

`vectors.json` holds synthetic saves and the exact decision each must produce. Run
`python3 test_entitlement.py` for the 91 checks; `make_vectors.py` regenerates the file.
**If a Go port agrees with `vectors.json`, the port is correct**
