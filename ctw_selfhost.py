#!/usr/bin/env python3
"""ctw_selfhost.py - a standalone server that restores the Social Club entitlement.

One process, standard library only. It answers the console on the ports the game uses and proxies
the rest, serving the decision from ctw_entitlement.py.

    UDP/53     DNS           answers the stats hosts with this machine's IP, forwards the rest
    TCP/80     NAS + stats   the GameSpy gamestats handshake
    TCP/443    NAS (TLS)     tunnelled to the upstream, which holds a certificate the DS accepts
    TCP/29920  gamestats     where the entitlement is served
    UDP/27900  availability  the QR2 "is the server up" reply
    TCP/29900  GPCM          proxied, and observed: the greet needs a token the console sends here

Needs root for the privileged ports. Set the console's WFC DNS (Auto-obtain DNS: No) to --ip.

    sudo python3 ctw_selfhost.py --ip 192.168.1.50 --upstream <host>
"""
import argparse
import base64
import datetime
import email.utils
import json
import os
import random
import re
import socket
import string
import struct
import sys
import threading
import time

# The decision lives in ctw_entitlement.py; keeping it separate is what makes this portable.
import ctw_entitlement as ctw

ARGS = None
STATS_HOSTS = ("gamestats.gs.nintendowifi.net", "gamestats2.gs.nintendowifi.net")
LOG_LOCK = threading.Lock()


def log(record):
    record["ts"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    line = json.dumps(record, ensure_ascii=False)
    print(json.dumps({k: record[k] for k in ("kind", "peer", "qname", "method", "path") if k in record}),
          flush=True)
    with LOG_LOCK:
        with open(ARGS.log, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


# ---------------------------------------------------------------- DNS
def parse_qname(pkt):
    i = 12
    labels = []
    while i < len(pkt) and pkt[i]:
        n = pkt[i]
        labels.append(pkt[i + 1:i + 1 + n].decode("latin-1"))
        i += 1 + n
    return ".".join(labels), i + 1


def dns_reply(pkt, qname, qend, ip):
    """Build an A-record answer for qname -> ip (TTL 60)."""
    try:
        ipb = socket.inet_aton(ip)
    except OSError:
        return None
    qtype, qclass = struct.unpack_from(">HH", pkt, qend)
    if qtype != 1:  # only A records matter here
        return None
    header = struct.pack(">HHHHHH", struct.unpack_from(">H", pkt, 0)[0], 0x8180, 1, 1, 0, 0)
    question = pkt[12:qend + 4]
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ipb
    return header + question + answer


def dns_forward(pkt, upstream, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (upstream, 53))
        return s.recvfrom(4096)[0]
    except OSError:
        return None
    finally:
        s.close()


def dns_loop():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ARGS.bind, ARGS.dns_port))
    print(f"DNS on {ARGS.bind}:{ARGS.dns_port} (stats -> {ARGS.ip}, rest -> {ARGS.upstream})", flush=True)
    while True:
        pkt, peer = s.recvfrom(2048)
        if len(pkt) < 12:
            continue
        qname, qend = parse_qname(pkt)
        host = qname.lower().rstrip(".")
        is_stats = any(host == h or host.endswith("." + h) for h in STATS_HOSTS)
            # Names in --forward bypass every redirect and are resolved by the upstream resolver.
        must_forward = any(host == f or host.endswith("." + f) for f in ARGS.forward_names)
            # UDP GameSpy services (master/presence/availability) go straight to the replacement server.
        udp_direct = any(k in host for k in ("master.gs.", ".ms0.", ".ms1.", ".ms2."))
        suffix_hit = next(
            (ip for suffix, ip in ARGS.redirects if host == suffix or host.endswith("." + suffix)), None)
        if must_forward:
            target = None
        elif is_stats:
            target = ARGS.ip
        elif suffix_hit and ARGS.proxy_ports and not udp_direct:
            target = ARGS.ip          # proxied: console talks to us, we tunnel to the upstream
        else:
            target = suffix_hit       # straight redirect (or nothing -> forward upstream)
        if target:
            ans = dns_reply(pkt, qname, qend, target)
            log({"kind": "dns", "peer": peer[0], "qname": qname,
                 "action": "diverted" if is_stats else "redirected", "ip": target})
            if ans:
                s.sendto(ans, peer)
        else:
            log({"kind": "dns", "peer": peer[0], "qname": qname, "action": "forwarded"})
            ans = dns_forward(pkt, ARGS.upstream)
            if ans:
                s.sendto(ans, peer)


# ---------------------------------------------------------------- HTTP
def token():
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(32))


STATS_TOKEN = {"value": None}


def parse_nas_token(body):
    """Pull the NAS-issued per-session values out of a NAS response (base64, '*' = padding)."""
    import base64 as _b64
    out = {}
    for kv in body.decode("latin-1").split("&"):
        k, _, v = kv.partition("=")
        k, v = k.strip(), v.strip()
        if k not in ("token", "challenge", "locator"):
            continue
        if k == "locator":
            out[k] = v
            continue
        s = v.replace("*", "=")
        try:
            out[k] = _b64.b64decode(s + "=" * (-len(s) % 4)).decode("latin-1")
        except Exception:  # noqa: BLE001
            out[k] = v
    if out.get("challenge"):
        out["value"] = out.get("token") or out["challenge"]
    elif out.get("token"):
        out["value"] = out["token"]
    return out


def nas_forward(conn, peer, port, head, body):
    """Forward a plaintext DWC NAS request upstream and relay the answer, logging both."""
    import socket as _socket
    host, _, up_port = ARGS.nas_upstream.partition(":")
    try:
        up = _socket.create_connection((host, int(up_port or 80)), timeout=15)
    except OSError as exc:
        log({"kind": "nas-error", "peer": peer[0], "upstream": ARGS.nas_upstream, "error": str(exc)})
        conn.close()
        return
    try:
        up.sendall(head + b"\r\n\r\n" + body)
        chunks = []
        up.settimeout(20)
        while True:
            d = up.recv(8192)
            if not d:
                break
            chunks.append(d)
            if sum(len(c) for c in chunks) > 65536:
                break
        resp = b"".join(chunks)
        rhead, _, rbody = resp.partition(b"\r\n\r\n")
        tok = parse_nas_token(rbody)
        if tok:
            STATS_TOKEN.update(tok)
        log({"kind": "nas-response", "peer": peer[0], "upstream": ARGS.nas_upstream,
             "head": rhead.decode("latin-1")[:600], "len": len(resp),
             "token_len": len(tok) if tok else 0,
             "body_ascii": rbody[:4096].decode("latin-1"), "body_hex": rbody[:1024].hex()})
        conn.sendall(resp)
    except OSError as exc:
        log({"kind": "nas-error", "peer": peer[0], "upstream": ARGS.nas_upstream, "error": str(exc)})
    finally:
        try:
            up.close()
        except OSError:
            pass
        conn.close()


def handle_http(conn, peer, port=None):
    port = port if port is not None else ARGS.http_port
    log({"kind": "conn", "port": port, "peer": peer[0]})
    try:
        conn.settimeout(10)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        if not buf:
            return
        head, _, rest = buf.partition(b"\r\n\r\n")
        # Plaintext NAS traffic (noSSL test ROM) goes upstream, and we keep a copy of both sides.
        if ARGS.nas_upstream and (b"nas." in buf[:2048] or b"/ac" in buf[:64]):
            log({"kind": "http", "port": port, "peer": peer[0], "action": "nas-forward",
                 "head": head[:600].decode("latin-1"), "body_ascii": rest[:4096].decode("latin-1")})
            nas_forward(conn, peer, port, head, rest)
            return
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = (lines[0].split(" ", 2) + ["", ""])[:3]
        headers = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length") or 0)
        body = rest
        while len(body) < length:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk
        query = {}
        if "?" in path:
            for pair in path.split("?", 1)[1].split("&"):
                k, _, v = pair.partition("=")
                query[k] = v
        rec = {
            "kind": "http",
            "port": port,
            "peer": peer[0],
            "method": method,
            "path": path,
            "host_header": headers.get("host"),
            "user_agent": headers.get("user-agent"),
            "headers": headers,
            "body_ascii": body[:4096].decode("latin-1"),
            "body_hex": body[:2048].hex(),
        }
            # The connection test needs the X-Organization: Nintendo marker, not just a 200 (else 52200).
        if "conntest" in (headers.get("host") or ""):
            rec["action"] = "conntest"
            payload = b"ok"
        elif "hash" not in query:
            rec["action"] = "challenge"
            payload = token().encode()
            rec["token"] = payload.decode()
        else:
            rec["action"] = "data"
            rec["hash"] = query.get("hash")
            rec["pid"] = query.get("pid")
            if "data" in query:
                try:
                    raw = base64.urlsafe_b64decode(query["data"] + "=" * (-len(query["data"]) % 4))
                    rec["data_len"] = len(raw)
                    rec["data_hex"] = raw[:512].hex()
                    rec["data_ascii"] = raw[:512].decode("latin-1")
                    rec["data_head_be32"] = raw[:4].hex()
                except Exception as exc:  # noqa: BLE001
                    rec["data_error"] = str(exc)
            payload = b""
        log(rec)
        if rec.get("action") == "conntest":
                # Mirror the reference reply: HTTP/1.0, its Server/Date headers, the Nintendo marker.
            resp = (b"HTTP/1.0 200 OK\r\n"
                    b"Server: Nintendo Wii (http)\r\n"
                    b"Date: " + email.utils.formatdate(usegmt=True).encode() + b"\r\n"
                    b"Content-type: text/html\r\n"
                    b"X-Organization: Nintendo\r\n"
                    b"Server: BigIP\r\n"
                    b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                    b"\r\n" + payload)
        else:
            resp = (b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/html\r\n" +
                    b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + payload)
        conn.sendall(resp)
    except Exception as exc:  # noqa: BLE001
        log({"kind": "http-error", "peer": peer[0], "error": repr(exc)})
    finally:
        conn.close()


def tunnel(conn, peer, port, upstream):
    """TCP proxy: log the opening bytes each way, then pump both directions."""
    try:
        up = socket.create_connection((upstream, port), timeout=8)
    except OSError as exc:
        log({"kind": "proxy-error", "port": port, "peer": peer[0], "upstream": upstream,
             "error": str(exc)})
        conn.close()
        return
    log({"kind": "proxy-open", "port": port, "peer": peer[0], "upstream": upstream})

    def pump(src, dst, tag):
        """Log EVERY chunk (lengths matter; hex is capped) plus the connection totals on close."""
        total = 0
        chunks = 0
        idles = 0
        idle_started = None
        try:
            src.settimeout(getattr(ARGS, "proxy_idle_timeout", 60.0))
            while True:
                try:
                    data = src.recv(4096)
                except socket.timeout:
                        # A read timeout is idle, not dead: GameSpy sessions go quiet between keepalives.
                        # Tearing the tunnel down here is what produced error 91010 about 60 s after a sync.
                    idles += 1
                    if idle_started is None:
                        idle_started = time.time()
                    if idles == 1 or idles % 10 == 0:
                        log({"kind": "proxy-idle", "port": port, "peer": peer[0], "dir": tag,
                             "idles": idles, "idle_s": round(time.time() - idle_started, 1),
                             "total": total})
                    cap = getattr(ARGS, "proxy_max_idle", 1800.0)
                    if cap and (time.time() - idle_started) > cap:
                        log({"kind": "proxy-idle-cap", "port": port, "peer": peer[0], "dir": tag,
                             "idle_s": round(time.time() - idle_started, 1)})
                        break
                    continue
                if not data:
                    break
                idles = 0
                idle_started = None
                total += len(data)
                chunks += 1
                log({"kind": "proxy", "port": port, "peer": peer[0], "dir": tag,
                     "chunk": chunks, "len": len(data), "total": total,
                     "hex": data[:512].hex()})
                dst.sendall(data)
        except OSError as exc:
            log({"kind": "proxy-eof", "port": port, "peer": peer[0], "dir": tag,
                 "chunks": chunks, "total": total, "error": str(exc)})
        else:
            log({"kind": "proxy-eof", "port": port, "peer": peer[0], "dir": tag,
                 "chunks": chunks, "total": total})
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t1 = threading.Thread(target=pump, args=(conn, up, "c->s"), daemon=True)
    t2 = threading.Thread(target=pump, args=(up, conn, "s->c"), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    try:
        conn.close()
        up.close()
    except OSError:
        pass


def udp_raw_loop(port):
    """Log UDP datagrams (GameSpy availability and presence speak UDP) and optionally reply."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ARGS.bind, port))
    reply = bytes.fromhex(ARGS.udp_reply) if ARGS.udp_reply else b""
    print(f"udp logger on {ARGS.bind}:{port} reply={reply.hex() or '(none)'}", flush=True)
    while True:
        data, peer = s.recvfrom(2048)
        log({"kind": "udp", "port": port, "peer": peer[0], "len": len(data),
             "hex": data[:256].hex(), "ascii": data[:256].decode("latin-1"),
             "replied": reply.hex()})
        if reply:
            s.sendto(reply, peer)


STATS_IN_KEY = b"GameSpy3D"      # server -> client. DAT_0211c0d0 (state 3) and DAT_0211c588
STATS_OUT_KEY = b"GameSpy3D"     # client -> server. BOTH directions use the same key: the GameSpy
    # The wire cipher is "GameSpy3D" in both directions; 'ProjectAphex' XORs the SDK's format-string
    # templates, not the wire.


def stats_xor(data, key=STATS_IN_KEY):
    """The module's cipher: an involution, so the same call encrypts and decrypts."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def stats_wire(msg, key=STATS_IN_KEY):
    r"""Encrypt the body but leave the trailing `inal\` in plaintext, or the peer cannot frame."""
    term = b"\\final\\"
    if msg.endswith(term):
        return stats_xor(msg[:-len(term)], key) + term
    return stats_xor(msg, key)


def stats_reply_for_client():
    r"""The session-key reply owed to the console's `uth\` message.

    Without it the console never sends its `\authp\` and waits out its budget (error 92070).
    """
    m = latest_lc2_message()
    if not m:
        return None
    lid = re.search(rb"\\sesskey\\(\d+)", m)
    if not lid:
        return None
    lid = lid.group(1).decode().lstrip("0") or "0"
    return b"\\lc\\2\\sesskey\\" + lid.encode() + b"\\proof\\0\\id\\1\\final\\"


def stats_pauthr_for_client(client_msg=""):
    r"""The auth reply owed to the console's `uthp\` message."""
    if isinstance(client_msg, bytes):
        client_msg = client_msg.decode("latin-1", "replace")

    def _val(m):
        if not m:
            return None
        v = m.group(1)
        return v.decode() if isinstance(v, bytes) else v

    lid = _val(re.search(r"\\lid\\(\d+)", client_msg or ""))
    pid = _val(re.search(r"\\pid\\(\d+)", client_msg or ""))
    if lid is None or pid is None:
        m = latest_lc2_message() or b""
        if lid is None:
            lid = _val(re.search(rb"\\sesskey\\(\d+)", m))
        if pid is None:
            pid = _val(re.search(rb"\\profileid\\(\d+)", m))
    if lid is None:
        return None
    lid = lid.lstrip("0") or "0"
    return b"\\pauthr\\" + (pid or "1").encode() + b"\\lid\\" + lid.encode() + b"\\final\\"


def stats_setpdr_for_client(client_msg=""):
    r"""Ack for the console's `\setpd\` upload, which lets it finish its sync."""
    if isinstance(client_msg, bytes):
        client_msg = client_msg.decode("latin-1", "replace")

    def _val(m):
        if not m:
            return None
        v = m.group(1)
        return v.decode() if isinstance(v, bytes) else v

    lid = _val(re.search(r"\\lid\\(\d+)", client_msg or ""))
    pid = _val(re.search(r"\\pid\\(\d+)", client_msg or ""))
    if lid is None or pid is None:
        m = latest_lc2_message() or b""
        if lid is None:
            lid = _val(re.search(rb"\\sesskey\\(\d+)", m))
        if pid is None:
            pid = _val(re.search(rb"\\profileid\\(\d+)", m))
    if lid is None or pid is None:
        return None
    lid = lid.lstrip("0") or "0"
    return (b"\\setpdr\\1\\lid\\" + lid.encode() + b"\\pid\\" + pid.encode()
            + b"\\mod\\" + str(int(time.time())).encode() + b"\\final\\")


STATS_PROFILES = {}     # (pid, ptype, dindex) -> the profile data section, verbatim


def _gs_pairs(s):
    r"""Parse a GameSpy `\keyalue\` message into a dict, last value winning."""
    t = s.split("\\")
    return {t[i]: t[i + 1] for i in range(1, len(t) - 1, 2)}


def remember_profile(client_msg):
    r"""Store the data section of a `\setpd\` upload so `\getpd\` can serve it back."""
    if isinstance(client_msg, bytes):
        client_msg = client_msg.decode("latin-1", "replace")
    if "\\setpd\\" not in client_msg:
        return
    body = client_msg.split("\\final\\")[0]
    head, _, rest = body.partition("\\data\\")
    f = _gs_pairs(head)
    STATS_PROFILES[(f.get("pid", "0"), f.get("ptype", "0"), f.get("dindex", "0"))] = rest
    log({"kind": "stats-profile-stored", "pid": f.get("pid"), "ptype": f.get("ptype"),
         "dindex": f.get("dindex"), "data_len": len(rest)})


SAVE_BLOB_BASE = ctw.SAVE_BLOB_BASE     # re-exported: the notes and logs refer to it by name


def _uploaded_save_bytes(stored_pairs):
    r"""The raw save the client uploaded. The `\SAVE\` blob starts at save offset 0x1EC."""
    return ctw.save_bytes_from_pairs(stored_pairs)


def progress_gate_ok(stored_pairs):
    """Should the Xin entitlement (.DLKEY00) be served for this upload? Returns (ok, why).

    The rule lives in ctw_entitlement.progress_gate_ok; this wrapper supplies the CLI's spec.
    """
    return ctw.progress_gate_ok(_uploaded_save_bytes(stored_pairs),
                                getattr(ARGS, "progress_gate", ctw.DEFAULT_GATE))


def sean_gate_ok(stored_pairs):
    """Should the Sean entitlement (.DLKEY01) be served? Same rule engine, its own spec."""
    return ctw.progress_gate_ok(_uploaded_save_bytes(stored_pairs),
                                getattr(ARGS, "sean_gate", ctw.DEFAULT_SEAN_GATE))


def stats_getpdr_for_client(client_msg=""):
    r"""Reply to `\getpd\`. The values come from ctw_entitlement.decide(); this is wire format only."""
    if isinstance(client_msg, bytes):
        client_msg = client_msg.decode("latin-1", "replace")
    body = (client_msg or "").split("\\final\\")[0]
    f = _gs_pairs(body)
    pid = f.get("pid", "1")
    ptype = f.get("ptype", "0")
    dindex = f.get("dindex", "0")
    lid = (f.get("lid") or "0").lstrip("0") or "0"
    keys = [k for k in (f.get("keys") or "").split("\x01") if k and k not in ("__cmd__", "__cmd_val__")]

    stored = STATS_PROFILES.get((pid, ptype, dindex), "")
    stored_pairs = _gs_pairs(stored) if stored else {}

    spec = getattr(ARGS, "progress_gate", ctw.DEFAULT_GATE)
    sean_spec = getattr(ARGS, "sean_gate", ctw.DEFAULT_SEAN_GATE)
    blob = ctw.save_bytes_from_pairs(stored_pairs)
    gate_ok, gate_why = ctw.progress_gate_ok(blob, spec)
    sean_ok, sean_why = ctw.progress_gate_ok(blob, sean_spec)

    decided = ctw.decide(
        keys, stored_pairs,
        dlkey_mask=int(getattr(ARGS, "dlkey_mask", 0) or 0),
        dlkey_value=getattr(ARGS, "dlkey_value", "1") or "1",
        gate=spec,
        sean_gate=sean_spec,
        savever_echo=bool(getattr(ARGS, "savever_echo", False)),
    )
    # .SAVEVER must echo the client's own identity word: serving a literal closes the reward gate.
    if getattr(ARGS, "savever", None) and "SAVEVER" in decided:
        decided["SAVEVER"] = str(int(ARGS.savever, 0))

    # Log either way, so a pass is not indistinguishable from the gate never running.
    if ".DLKEY00" in keys:
        log({"kind": "progress-gate", "key": ".DLKEY00", "served": bool(gate_ok),
             "rule": spec, "why": gate_why})
    if ".DLKEY01" in keys:
        log({"kind": "progress-gate", "key": ".DLKEY01", "served": bool(sean_ok),
             "rule": sean_spec, "why": sean_why})

    data = ""
    for k in keys:
        data += "\\" + k + "\\" + decided.get(k, "")
    if not keys:
        data = stored

    msg = (b"\\getpdr\\1\\lid\\" + lid.encode() + b"\\pid\\" + pid.encode()
           + b"\\mod\\" + str(int(time.time())).encode()
           + b"\\length\\" + str(len(data)).encode()
           + b"\\data\\" + data.encode("latin-1", "replace") + b"\\final\\")
    # the reference's odd-backslash guard: an empty field must be terminated before \final\
    if msg.count(b"\\") % 2:
        msg = msg.replace(b"\\final\\", b"\\\\final\\")
    return msg


def _savever_from_upload(stored_pairs):
    """The save identity word the client uploaded, as the value for .SAVEVER."""
    return ctw.savever_from_save(_uploaded_save_bytes(stored_pairs))


def stats_followup_for_client():
    """The state-5 stats payload, which goes out after the state-4 reply, not before."""
    m = latest_lc2_message()
    if not m:
        return None
    lid = re.search(rb"\\sesskey\\(\d+)", m)
    lt = re.search(rb"\\lt\\([A-Za-z0-9_.-]+)", m)
    if not lid:
        return None
    lid = lid.group(1).decode().lstrip("0") or "0"
    token = lt.group(1).decode() if lt else (STATS_TOKEN.get("challenge") or "0")
    msg = b"\\pauthr\\" + token.encode() + b"\\lid\\" + lid.encode() + b"\\final\\"
    return msg if len(msg) <= 64 else None


def latest_lc2_message():
    r"""Most recent `\lc\2` session message the proxy saw on GPCM (same console session)."""
    try:
        with open(ARGS.log) as fh:
            for line in reversed(fh.readlines()[-500:]):
                try:
                    rec = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                hx = rec.get("hex") or ""
                if hx.startswith("5c6c635c32"):        # "\lc\2"
                    return bytes.fromhex(hx)
    except OSError:
        pass
    return None


def latest_sesskey_echo():
    r"""The client\'s own `\status\` message on GPCM, which echoes its sesskey as a number."""
    try:
        with open(ARGS.log) as fh:
            for line in reversed(fh.readlines()[-500:]):
                try:
                    rec = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                hx = rec.get("hex") or ""
                if hx.startswith("5c7374617475735c") and b"\\sesskey\\" in bytes.fromhex(hx):
                    return bytes.fromhex(hx)
    except OSError:
        pass
    return None


def _lc2_field(m, marker):
    r"""Value following `marker` in a `\key\value\` message, where marker includes both backslashes."""
    i = m.find(marker)
    if i < 0:
        return None
    rest = m[i + len(marker):]
    j = rest.find(b"\\")
    if j >= 0:
        rest = rest[:j]
    return rest.decode("latin-1") or None


def stats_greet_session():
    """Resolve every value the stats greet needs, so it can be tested directly.

    Returns val/lid/pid/lt/av plus a source for each. A falsy val means the greet cannot be sent,
    and the client then waits out its 20 s timeout and reports error 92070.
    """
    val, val_src = None, None
    if ARGS.pauthr_value == "challenge" and STATS_TOKEN.get("challenge"):
        val, val_src = STATS_TOKEN["challenge"], "nas-challenge"
    elif STATS_TOKEN.get("value"):
        val, val_src = STATS_TOKEN["value"], "nas-token"
    elif ARGS.pauthr_token:
        val, val_src = ARGS.pauthr_token, "cli"

    lid, lid_src, pid, pid_src, lt, lt_src = ARGS.pauthr_lid, None, None, None, None, None
    if ARGS.pauthr_lid:
        lid_src = "cli"
    m = latest_lc2_message()
    if m:
        sk = _lc2_field(m, b"\\sesskey\\")
        if sk and not lid:
            lid, lid_src = sk.lstrip("0") or "0", "lc2"
        pf = _lc2_field(m, b"\\profileid\\")
        if pf:
            pid, pid_src = pf, "lc2"
        ltv = _lc2_field(m, b"\\lt\\")
        if ltv:
            lt, lt_src = ltv, "lc2"

    if not val and lt:
        val, val_src = lt, "lc2-lt-fallback"

    if not lid:
        lid, lid_src = "".join(random.choice(string.digits) for _ in range(8)), "random"

    if ARGS.pauthr_value == "lt" and lt:
        av, av_src = lt, lt_src
    elif ARGS.pauthr_value == "token" and STATS_TOKEN.get("value"):
        av, av_src = STATS_TOKEN["value"], "nas-token"
    elif lt:
        av, av_src = lt, lt_src
    else:
        av, av_src = val, val_src

    return {"val": val, "val_src": val_src, "lid": lid, "lid_src": lid_src,
            "pid": pid, "pid_src": pid_src, "lt": lt, "lt_src": lt_src,
            "av": av, "av_src": av_src}


def handle_raw(conn, peer, port):
    """Log whatever arrives on an auxiliary port; serve HTTP-looking requests; never speak first."""
    if ARGS.proxy_ports and port in ARGS.proxy_ports and ARGS.proxy_upstream:
        tunnel(conn, peer, port, ARGS.proxy_upstream)
        return
    log({"kind": "raw-open", "port": port, "peer": peer[0]})
    try:
        if ARGS.raw_greet == "pauthr":
                # The dispatcher is silent until the server speaks first, and accepts only \pauthr\,
                # \getpidr\, \getpdr\ and \setpdr\.
            g = stats_greet_session()
            val, val_src = g["val"], g["val_src"]
            lid, lid_src = g["lid"], g["lid_src"]
            pid, pid_src = g["pid"], g["pid_src"]
            lt, lt_src = g["lt"], g["lt_src"]
            av, av_src = g["av"], g["av_src"]
            if val:
                    # The first message must be a challenge: the SDK's SendChallengeResponse() looks for
                    # "challenge" and closes the socket if it is absent.
                steps = [(0.0, b"\\challenge\\" + av.encode() + b"\\lid\\" + lid.encode() + b"\\final\\")]
                want = set(ARGS.greet_steps.split(",")) if ARGS.greet_steps else None

                def _send_sequence():
                    t0 = time.time()
                    for delay, msg in steps:
                        tag = msg.split(b"\\")[1].decode("latin-1", "replace")
                        if want and tag not in want:
                            log({"kind": "raw-greet", "port": port, "peer": peer[0], "sent": None,
                                 "step": tag, "note": "skipped (not in --greet-steps)"})
                            continue
                        time.sleep(max(0.0, delay - (time.time() - t0)))
                        wire = stats_wire(msg)
                        try:
                            conn.sendall(wire)
                        except OSError as exc:
                            log({"kind": "raw-greet", "port": port, "peer": peer[0], "sent": None,
                                 "step": tag, "error": str(exc), "note": "send failed"})
                            return
                        log({"kind": "raw-greet", "port": port, "peer": peer[0],
                             "sent": msg.decode("latin-1", "replace"), "step": tag,
                             "delay": round(delay, 2), "msg_len": len(msg),
                             "wire_hex": wire[:64].hex(), "encrypted": True,
                             "meets_38_byte_minimum": len(msg) >= 0x26,
                             "fits_64_byte_buffer": len(msg) <= 64})

                log({"kind": "raw-greet-plan", "port": port, "peer": peer[0],
                     "value_source": av_src, "value_len": len(av), "lt_source": lt_src,
                     "lid": lid, "lid_source": lid_src, "pid": pid, "pid_source": pid_src,
                     "steps": [m.split(b"\\")[1].decode("latin-1", "replace") for _, m in steps]})
                threading.Thread(target=_send_sequence, daemon=True).start()
            else:
                log({"kind": "raw-greet", "port": port, "peer": peer[0], "sent": None,
                     "note": "no NAS value captured yet"})
        if ARGS.raw_greet == "lc2":
            msg = latest_lc2_message()
            if msg:
                conn.sendall(msg)
                log({"kind": "raw-greet2", "port": port, "peer": peer[0],
                     "sent": msg[:160].decode("latin-1", "replace")})
            else:
                log({"kind": "raw-greet2", "port": port, "peer": peer[0], "sent": None,
                     "note": "no \\lc\\2 captured yet this session"})
        if ARGS.raw_greet == "lc1":
                # Match the format the library's sibling service sends: \lc\1\challenge\<10 uppercase>\
                # id\1\final\. Every real challenge this console saw was 10 uppercase letters.
            chal = "".join(random.choice(string.ascii_uppercase) for _ in range(10))
            greet = (b"\\lc\\1\\challenge\\" + chal.encode() + b"\\id\\1\\final\\")
            conn.sendall(greet)
            log({"kind": "raw-greet", "port": port, "peer": peer[0], "sent": greet.decode("latin-1")})
                # Plan B: no reply within a few seconds means replay this session's real \lc\2 message.
            conn.settimeout(ARGS.raw_greet_wait)
            peer_closed = False
            try:
                answered = bool(conn.recv(8, socket.MSG_PEEK))
                peer_closed = not answered
            except socket.timeout:
                answered = False
            except OSError:
                answered = True
            if peer_closed:
                log({"kind": "raw-greet2", "port": port, "peer": peer[0], "sent": None,
                     "note": "client closed right after probe 1 - probe 2 skipped"})
            elif not answered:
                msg = latest_lc2_message()
                if msg:
                    conn.sendall(msg)
                    log({"kind": "raw-greet2", "port": port, "peer": peer[0],
                         "sent": msg[:160].decode("latin-1", "replace")})
                else:
                    log({"kind": "raw-greet2", "port": port, "peer": peer[0],
                         "sent": None, "note": "no \\lc\\2 captured yet this session"})
        conn.settimeout(ARGS.raw_timeout)
            # Peek first: HTTP requests are handed to handle_http untouched.
        peek = conn.recv(8, socket.MSG_PEEK)
        if not peek:
            log({"kind": "raw", "port": port, "peer": peer[0], "action": "empty-connection"})
            return
        if peek.upper().startswith((b"GET ", b"POST", b"PUT ", b"HEAD", b"OPTI")):
            handle_http(conn, peer, port)
            return
        total = 0
        buf = b""
        replied = {"sesskey": False, "pauthr": False, "setpdr": 0, "getpdr": 0}
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                log({"kind": "raw-eof", "port": port, "peer": peer[0], "total": total})
                break
            total += len(chunk)
            rec = {"kind": "raw-chunk", "port": port, "peer": peer[0], "len": len(chunk),
                   "total": total, "hex": chunk[:512].hex(),
                   "ascii": chunk[:512].decode("latin-1")}
            if port == 29920:
                buf += chunk
                    # The cipher restarts per message and \final\ travels in plaintext.
                msgs = [stats_xor(p, STATS_OUT_KEY).decode("latin-1", "replace")
                        for p in buf.split(b"\\final\\")[:-1]]
                rec["decoded_chunk"] = stats_xor(chunk, STATS_OUT_KEY).decode("latin-1", "replace")[:512]
                rec["decoded_messages"] = msgs[:4]
                joined = " ".join(msgs)
                    # Two replies are owed, in order: \auth\ -> \lc\2\sesskey\..., then \authp\ ->
                    # \pauthr\... Each is a separate write; a concatenated pair fails the parse.
                wants = []
                    # The console makes several \getpd\ requests per session, so these are counts, not
                    # one-shot flags. Match decoded messages, never the raw buffer.
                setpd_reqs = [m for m in msgs if "\\setpd\\" in m]
                while replied["setpdr"] < len(setpd_reqs):
                    req = setpd_reqs[replied["setpdr"]]
                    replied["setpdr"] += 1
                    remember_profile(req)
                    wants.append(("setpdr", stats_setpdr_for_client(req)))
                getpd_reqs = [m for m in msgs if "\\getpd\\" in m]
                while replied["getpdr"] < len(getpd_reqs):
                    req = getpd_reqs[replied["getpdr"]]
                    replied["getpdr"] += 1
                    wants.append(("getpdr", stats_getpdr_for_client(req)))
                if "\\authp\\" in joined and not replied["pauthr"]:
                    replied["pauthr"] = True
                    wants.append(("pauthr", stats_pauthr_for_client(joined)))
                elif "\\auth\\" in joined and not replied["sesskey"]:
                    replied["sesskey"] = True
                    wants.append(("sesskey", stats_reply_for_client()))
                for _kind, want in wants:
                    if not want:
                        continue
                    try:
                        wire = stats_wire(want)
                        conn.sendall(wire)
                        rec.setdefault("replies", []).append(
                            {"kind": _kind, "sent": want.decode("latin-1", "replace")})
                    except OSError as exc:
                        rec["reply_error"] = str(exc)
                    # Diagnosis only. DLKEY11 awards money, not content, and volunteering values for keys
                    # the client did not upload makes it stall past the Ok button.
            log(rec)
    except Exception as exc:  # noqa: BLE001
        log({"kind": "raw-timeout", "port": port, "peer": peer[0], "error": repr(exc)})
    finally:
        conn.close()


def raw_loop(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ARGS.bind, port))
    s.listen(8)
    print(f"raw TCP logger on {ARGS.bind}:{port}", flush=True)
    while True:
        conn, peer = s.accept()
        threading.Thread(target=handle_raw, args=(conn, peer, port), daemon=True).start()


def http_loop():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ARGS.bind, ARGS.http_port))
    s.listen(16)
    print(f"HTTP on {ARGS.bind}:{ARGS.http_port} -> {ARGS.log}", flush=True)
    while True:
        conn, peer = s.accept()
        threading.Thread(target=handle_http, args=(conn, peer), daemon=True).start()


def main():
    global ARGS
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", help="IP to answer the stats hosts with (default: auto-detect)")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--dns-port", type=int, default=53)
    ap.add_argument("--http-port", type=int, default=80)
    ap.add_argument("--upstream", default="95.217.77.181",
                    help="resolver for names this server does not answer itself. Has a working "
                         "default; override to use a resolver you trust.")
    ap.add_argument("--redirect", action="append", default=[], metavar="SUFFIX=IP",
                    help="answer names under SUFFIX with IP, e.g. nintendowifi.net=172.104.88.237. "
                         "The stats hosts always win and still come to us. Repeatable.")
    ap.add_argument("--raw-port", action="append", default=[], type=int,
                    help="extra TCP port to log raw traffic on (e.g. 443 in case the client uses "
                         "HTTPS, 28910 for GameSpy GPCM). Repeatable.")
    ap.add_argument("--proxy-port", action="append", default=[], type=int,
                    help="TCP port to proxy to --proxy-upstream while logging both directions "
                         "(e.g. 80, 443, 28910). Names that match a --redirect suffix then resolve "
                         "to us instead of straight to the upstream. Repeatable.")
    ap.add_argument("--progress-gate", default=ctw.DEFAULT_GATE, metavar="SPEC",
                    help="comma list of checks against the uploaded save that must ALL hold before "
                         "the Xin entitlement (.DLKEY00) is served: offset:mask:value, offset:!=value, "
                         "offset:==value, or offset:bits:count for a bit run. The client does no "
                         "prerequisite check of its own, so the server must. Default is the story "
                         "marker plus both Lions of Fo. See progress_gate_ok; use 'off' to serve "
                         "unconditionally.")
    ap.add_argument("--sean-gate", default=ctw.DEFAULT_SEAN_GATE, metavar="SPEC",
                    help="the same rule language, applied to the Sean entitlement (.DLKEY01). Default "
                         "requires all 100 security cameras to be destroyed.")
    ap.add_argument("--proxy-idle-timeout", type=float, default=60.0,
                    help="per-read timeout on a proxied connection. A read timeout is treated as "
                         "IDLE (the tunnel stays open) - closing on it is what caused the console's "
                         "error 91010 ~60 s after a sync.")
    ap.add_argument("--proxy-max-idle", type=float, default=1800.0,
                    help="give up on a proxied connection after this many seconds of continuous "
                         "idle (0 = never).")
    ap.add_argument("--proxy-upstream", default=None,
                    help="host/IP the proxied ports are forwarded to (e.g. 172.104.88.237)")
    ap.add_argument("--raw-greet", default="none", choices=["none", "lc1", "lc2", "pauthr"],
                    help="message to send as soon as a client connects on a raw port. 'pauthr' sends "
                         "\\pauthr\\<nas token>\\lid\\<n>\\final\\ - the message the ROM's stats "
                         "dispatcher requires before the client will send anything. 'lc1'/'lc2' are "
                         "the older GPCM-style probes (refuted).")
    ap.add_argument("--pauthr-token", default=None,
                    help="token to use for the pauthr probe when no NAS token was captured yet "
                         "(testing only; real rounds take it from the NAS response)")
    ap.add_argument("--greet-steps", default=None,
                    help="comma list of greet steps to actually send (pauthr,getpidr,getpdr); "
                         "default: all")
    ap.add_argument("--pauthr-lid", default=None,
                    help="lid value for the pauthr probe (default: the client's own \\status\\ sesskey)")
    ap.add_argument("--pauthr-value", default="lt", choices=["lt", "challenge", "token"],
                    help="which session value to send as the pauthr field. 'lt' (default) is the "
                         "22-char login token from the client's \\lc\\2\\ message, giving a 50-byte "
                         "message; 'challenge' is the 8-char NAS value (36 bytes - below the 38-byte "
                         "parse minimum); 'token' is the 111-char profile token (overflows the buffer)")
    ap.add_argument("--nas-upstream", default=None, metavar="HOST[:PORT]",
                    help="forward plaintext (noSSL) DWC NAS requests here and relay+log the answer, "
                         "e.g. 172.104.88.237:80. Without it, NAS-looking requests get the local stub.")
    ap.add_argument("--raw-greet-wait", type=float, default=4.0,
                    help="with --raw-greet lc1: seconds to wait for a reply before replaying the "
                         "session's own \\lc\\2 message as a second probe")
    ap.add_argument("--raw-timeout", type=float, default=90.0,
                    help="seconds to wait for data on a raw (non-proxied) port before giving up; "
                         "the console can be silent for a while on the gamestats port")
    ap.add_argument("--udp-port", action="append", default=[], type=int,
                    help="UDP port to log (and optionally answer) - GameSpy availability/presence "
                         "use 27900. Repeatable.")
    ap.add_argument("--udp-reply", default="",
                    help="hex bytes to send back to each UDP datagram, e.g. 0000 (empty = log only)")
    ap.add_argument("--forward", action="append", default=[], metavar="NAME",
                    help="name (or suffix) that bypasses redirects and is resolved by --upstream, "
                         "e.g. conntest.nintendowifi.net. Repeatable.")
    ap.add_argument("--dlkey-mask", type=lambda s: int(s, 0), default=0,
                    help="bit N set -> the reply to \\getpd\\ carries --dlkey-value for .DLKEYNN. "
                         "Default 0 = all empty (the verified-working behaviour). 65535 = all 16.")
    ap.add_argument("--dlkey-value", default="1",
                    help="value served for the .DLKEY## keys selected by --dlkey-mask")
    ap.add_argument("--savever", default=None, metavar="N",
                    help="literal value served for .SAVEVER (the gate). The client compares it "
                         "against [0x021f113c]; measured 34768057 (0x021284b9) during a session.")
    ap.add_argument("--savever-echo", action="store_true",
                    help="serve .SAVEVER from the uploaded SAVE blob (save[0x230]). This is the "
                         "gate: the client only applies the .DLKEY## reward bits when the value it "
                         "parsed matches the identity word in its loaded save.")
    ap.add_argument("--log", default="logs/capture.jsonl")
    ARGS = ap.parse_args()
    ARGS.proxy_ports = ARGS.proxy_port
    ARGS.forward_names = [n.lower().strip(".") for n in ARGS.forward]
    ARGS.redirects = []
    for spec in ARGS.redirect:
        suffix, _, ip = spec.partition("=")
        if not suffix or not ip:
            ap.error(f"--redirect wants SUFFIX=IP, got {spec!r}")
        ARGS.redirects.append((suffix.lower().strip("."), ip.strip()))
    if not ARGS.ip:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 53))
            ARGS.ip = probe.getsockname()[0]
        except OSError:
            ARGS.ip = "127.0.0.1"
        finally:
            probe.close()
    os.makedirs(os.path.dirname(os.path.abspath(ARGS.log)), exist_ok=True)
    threading.Thread(target=dns_loop, daemon=True).start()
    for port in sorted(set(ARGS.raw_port) | set(ARGS.proxy_ports)):
        threading.Thread(target=raw_loop, args=(port,), daemon=True).start()
    for port in ARGS.udp_port:
        threading.Thread(target=udp_raw_loop, args=(port,), daemon=True).start()
    try:
        http_loop()
    except KeyboardInterrupt:
        print("\nstopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
