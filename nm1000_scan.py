#!/usr/bin/env python3
"""Neat NM-1000 (VID 1f44 / PID 0001) Linux driver v1.

Replays captured Windows USB traffic to scan on Linux:
  1. EP0 vendor init (per mode/DPI) from nm1000-ctrl-*.json
     (ordered vendor OUT writes + vendor IN reads, in captured order).
  2. Bulk OUT calibration + commands from nm1000-*-out.bin
     (split in captured transfer lengths).
  3. Bulk IN image from EP 0x81 until timeout -> scan.raw
  4. Render to PNG (gray 'L' or color RGB interleaved hypotheses).

Captured protocol summary (see LLM_PROMPT.md + analysis):
- Descriptors: 1f44:0001, IF 0 FF/FF/FF, EP 0x81 bulk IN (image),
  EP 0x02 bulk OUT (cal/commands), EP 0x83 intr IN (unused, 0 pkts).
- Bulk EP2 is mode/DPI-INDEPENDENT for 512B blocks (identical across
  gray/color and 150/300); mode + DPI live in EP0 vendor OUT 64B tables
  (setup 40 04 83 00 00 00 40 00):
    tbl[9] (01a0..) byte19: 00=gray, 02=color (mode flag)
    tbl[10] (2404..) bytes 33/35: DPI/mode-dependent gain
      gray150 85:43:96, gray300 82:a3:93, gray600 81:73:97 (3 diffs),
      color300 80:e3:90
    tbl[11] (6600..) byte47: 04=gray, 00=color; plus DPI bytes 13/15
  First 3x (tbl0-8) identical across all scans (generic init);
  last 2x (tbl9-14) carry mode/DPI (programmed twice identically).
- Bulk EP2 calibration IS per-scan measured shading (host->scanner):
  10808B x3 at 150/300 (same head 0000..feff..), 21608B x3 at 600
  (doubles with sensor width). Replay verbatim for v1; expect mild
  shading error if lamp/paper differ.
- Image widths (exact divisors of captured IN totals):
  gray300: 2548 x 1562 (3979976 B, rem 0; NOT 2550)
  gray150: 1348 x 703 (947644 B; note 1348 != 2548/2 -- validate visually)
  gray600: 5100 x 2965 (15121500 B)
  color300: 2548 px interleaved RGB, 7644 B/line x 4463 lines + 4 B tail
    (34115176 B; planar split also plausible -- both PNGs saved).
- Empty feeder: bulk OUT 4B 00000000 probe (frame 55, unique to error path;
  success scans' smallest write is 2B 4605), then control-only pattern,
  no image. Driver reports NO_DOCS (exit 2) on zero-length image.
- Long-scan polling (~700x 2B OUT + 2B/256B IN at 600 DPI, plus vendor
  IN/OUT interleaved between bulk strips) is SKIPPED for v1 -- scanner
  streams autonomously; short scans complete without it. If 600 DPI
  stalls, capture will show it (see --verbose).

Usage:
  python3 nm1000_scan.py --mode gray --dpi 300 --out scan.png --raw scan.raw
  python3 nm1000_scan.py --mode color --dpi 300 --out scan-color.png
  python3 nm1000_scan.py --dry-run --mode gray --dpi 300   # parse only, no USB

Permissions (device is 1f44:0001, root:root by default):
  sudo cp 60-neat-nm1000.rules /etc/udev/rules.d/
  sudo udevadm control --reload-rules && sudo udevadm trigger
  # then replug scanner; check: ls -l /dev/bus/usb/*/* should show
  # group 'scanner' with rw. User must be in 'scanner' (or 'plugdev').

Requires: pyusb, libusb-1.0, pillow.
"""
import argparse
import json
import pathlib
import struct
import sys

VID, PID = 0x1F44, 0x0001
EP_BULK_IN = 0x81
EP_BULK_OUT = 0x02
HERE = pathlib.Path(__file__).resolve().parent

# Per-mode verified parameters (pcap ground truth).
# b8200: vendor-8200 framing (setup 4004820001000800) sent BEFORE *every*
#   bulk OUT chunk including the first (pcap: 004001 precedes first cal).
# post2e/post1000: 46B/16B 8300 payloads of the motor-start sequence.
# img8200: per-strip image framing (setup 4004820000000800) -- MODE/DPI
#   SPECIFIC (using another mode's value stalls with lamp-on-no-feed).
# strip_big/strip_small: bulk IN strip sizes (exact-size reads).
MODE_CFG = {
    ("gray", 150): dict(
        json="nm1000-ctrl-gray150.json", blob="nm1000-150gray-out.bin",
        splits=(10808, 10808, 10808, 512, 512, 512, 32, 16, 2),
        b8200=("00400110382a0000", "00a00110382a0000", "00000210382a0000",
               "0000000100020000", "0002000100020000", "0004000100020000",
               "0000001020000000", "0080001010000000", "00c0001002000000"),
        post2e="02583854396021086454654160206100620069088f00900091009200936e950196a597e00a206a013d003e003f01",
        post1000="02506a043d003e003f01350036013777",
        img8200="0000001010950000",
        tail2800="0508c500c600bd00be47c700c800c900ca000414341f3000319f320a338f2c012d2c3d003e003f01",
        tail0a00="0900a000250026112794",
        tail0400=('10021158', '1204137e', '1406158b'), strip_big=37888, strip_small=272,
        width=1272, color=False, cycle=0.216),
    ("gray", 300): dict(
        json="nm1000-ctrl-gray300.json", blob="nm1000-300gray-out.bin",
        splits=(10808, 10808, 10808, 512, 512, 512, 32, 8, 2),
        b8200=("00400110382a0000", "00a00110382a0000", "00000210382a0000",
               "0000000100020000", "0002000100020000", "0004000100020000",
               "0000001020000000", "0080001008000000", "00c0001002000000"),
        post2e="0258382a39302104642a651160206100620069048f0090009100920093dc950196a597e00a206a013d003e003f01",
        post1000="02506a043d003e003f013500360137dd",
        img8200="00000010d4f80000",
        tail2800="0508c500c600bd00be47c700c800c900ca000414341f300031a7320a339b2c022d583d003e003f01",
        tail0a00="0900a000250026232728",
        tail0400=('10021158', '1204137e', '1406158b'), strip_big=63488, strip_small=212,
        width=2548, color=False, cycle=0.090),
    ("color", 300): dict(
        json="nm1000-ctrl-color300.json", blob="nm1000-300color-out.bin",
        splits=(10808, 10808, 10808, 512, 512, 512, 32, 8, 2),
        b8200=("00400110382a0000", "00a00110382a0000", "00000210382a0000",
               "0000000100020000", "0002000100020000", "0004000100020000",
               "0000001020000000", "0080001008000000", "00c0001002000000"),
        post2e="0258380e39102104640d65f160206100620069048f009000910092029394950196a597e00a206a013d003e003f01",
        post1000="02506a043d003e003f01350036053799",
        img8200="00000010e0ee0000",
        tail2800="0508c500c600bd00be47c700c800c900ca000410341f300031a7320a339b2c022d583d003e003f01",
        tail0a00="0900a000250026692778",
        tail0400=('1006116e', '120613a0', '1406156e'), strip_big=60928, strip_small=224,
        width=2548, color=True, cycle=0.038, layout="lineseq-rgb"),
    ("gray", 600): dict(
        json="nm1000-ctrl-gray600.json", blob="nm1000-600gray-out.bin",
        # Blob holds 21608x3+512x3+32; trailing 8+2 (b80b/dc05) appended literally.
        splits=(21608, 21608, 21608, 512, 512, 512, 32),
        b8200=("0040011068540000", "00c0011068540000", "0040021068540000",
               "0000000100020000", "0002000100020000", "0004000100020000",
               "0000001020000000"),
        extra_tails=(("0080001008000000", "b80bb80bb80bb80b"),
                     ("00c0001002000000", "dc05")),
        post2e="02583817397021046417656b60206100620069048f0090009100920193b8950196a597e00a206a013d003e003f01",
        post1000="02506a043d003e003f01350036073778",
        img8200="0000001010ef0000",
        tail2800="0508c500c600bd00be07c700c800c900ca00041434053000319a321433862c022d583d003e003f01",
        tail0a00="0900a000250026462750",
        tail0400=('10031108', '120713c2', '140c1545'), strip_big=60928, strip_small=272,
        width=5100, color=False, is600=True, frame_first=True, cycle=0.039),
    ("color", 150): dict(
        json="nm1000-ctrl-color150.json", blob="nm1000-150color-out.bin",
        splits=(10808, 10808, 10808, 512, 512, 512, 32, 16, 2),
        b8200=("00400110382a0000", "00a00110382a0000", "00000210382a0000",
               "0000000100020000", "0002000100020000", "0004000100020000",
               "0000001020000000", "0080001010000000", "00c0001002000000"),
        post2e="0258381c39202108641c650160206100620069088f00900091009201934a950196a597e00a206a013d003e003f01",
        post1000="02506a043d003e003f01350036013765",
        img8200="0000001068fd0000",
        tail2800="0508c500c600bd00be47c700c800c900ca000410341f3000319f320a338f2c012d2c3d003e003f01",
        tail0a00="0900a0002500263427bc",
        tail0400=('1006116e', '120613a0', '1406156e'), strip_big=64512, strip_small=360,
        width=1272, color=True, experimental=True, cycle=0.216),
}
# Back-compat aliases used by --dry-run summary.
BULK_BLOBS = {k: v["blob"] for k, v in MODE_CFG.items()}
CTRL_JSONS = {k: v["json"] for k, v in MODE_CFG.items()}
RENDER_WIDTHS = {k: v["width"] for k, v in MODE_CFG.items()}
# Legacy bulk-only splits (kept for --skip-ctrl path).
BULK_SPLITS = {("gray", 150): (10808, 10808, 10808, 512, 512, 512, 32, 16, 2),
               ("gray", 300): (10808, 10808, 10808, 512, 512, 512, 32, 8, 2),
               ("color", 300): (10808, 10808, 10808, 512, 512, 512, 32, 8, 2),
               ("gray", 600): (21608, 21608, 21608, 512, 512, 512, 32)}
# Vendor 8200 payloads exist in pcap between bulks but scanner streams without them for short scans;
# keeping simple bulk replay for now; if 600 DPI stalls, vendor interleaving will be added)
VENDOR_8200_PAYLOADS = {}


def parse_setup(setup_hex):
    b = bytes.fromhex(setup_hex)
    assert len(b) == 8, setup_hex
    bm, req = b[0], b[1]
    val = b[2] + (b[3] << 8)
    idx = b[4] + (b[5] << 8)
    length = b[6] + (b[7] << 8)
    return bm, req, val, idx, length


CTRL_PACE = 0.008   # Windows gaps ~4ms; 8ms is safe on slow rails.
BULK_PACE = 0.03


def load_ctrl_script(mode, dpi):
    p = HERE / CTRL_JSONS[(mode, dpi)]
    with open(p) as f:
        return json.load(f)


def replay_ctrl(dev, script, verbose=False, timeout=2000):
    """Replay ordered vendor control ops. IN data is read and discarded
    (logged in verbose); OUT payloads are written verbatim."""
    import usb.util

    n_in = n_out = 0
    for op in script:
        bm, req, val, idx, wlen = parse_setup(op["setup"])
        if op["op"] == "out":
            payload = bytes.fromhex(op["payload"])
            assert len(payload) == wlen, (op["setup"], len(payload), wlen)
            if verbose:
                print(f"  CTRL OUT bm={bm:02x} req={req:02x} "
                      f"val={val:04x} idx={idx:04x} len={wlen} "
                      f"payload={op['payload'][:32]}...")
            dev.ctrl_transfer(bm, req, val, idx, payload, timeout=timeout)
            n_out += 1
        else:
            if verbose:
                print(f"  CTRL IN  bm={bm:02x} req={req:02x} "
                      f"val={val:04x} idx={idx:04x} len={op['len']}")
            data = dev.ctrl_transfer(bm, req, val, idx, op["len"],
                                     timeout=timeout)
            n_in += 1
            if verbose and len(data) <= 16:
                print(f"    -> {bytes(data).hex()}")
    if verbose:
        print(f"  ctrl replay done: {n_out} OUT + {n_in} IN")
    return n_in, n_out


def replay_bulk_out(dev, mode, dpi, verbose=False, timeout=5000):
    """Legacy bulk OUT (kept for --skip-ctrl path and dry-run validation).
    For live scans, main() now uses replay_full_pcap() which includes vendor
    8200 interleaving and post-bulk vendors required for motor/image (see pcap
    idx 422-595). This function remains for compatibility."""
    import usb.core
    blob_path = HERE / BULK_BLOBS[(mode, dpi)]
    blob = blob_path.read_bytes()
    split = BULK_SPLITS[(mode, dpi)]
    assert len(blob) == sum(split), \
        f"{blob_path} len {len(blob)} != split sum {sum(split)} {split}"
    off = 0
    for i, ln in enumerate(split):
        chunk = blob[off:off + ln]
        if verbose:
            print(f"  BULK OUT {i}: {ln} B head={chunk[:16].hex()}...")
        try:
            dev.write(EP_BULK_OUT, chunk, timeout=timeout)
        except usb.core.USBTimeoutError as e:
            if verbose:
                print(f"  BULK OUT {i} timeout ({e}) -> likely NO PAPER (empty feeder)")
            try:
                dev.clear_halt(EP_BULK_OUT)
                dev.clear_halt(EP_BULK_IN)
            except Exception:
                pass
            raise
        off += ln
    if verbose:
        print(f"  bulk OUT done: {len(blob)} B in {len(split)} writes")
    return len(blob)


def _xfer_once(dev, op, timeout):
    # Single attempt of one script op. Returns response hex (IN) or "".
    if op["op"] == "bulk":
        assert op["len"] <= 64, op
        dev.write(EP_BULK_OUT, bytes.fromhex(op["data"]), timeout=timeout)
        return ""
    bm, req, val, idx, wlen = parse_setup(op["setup"])
    if op["op"] == "out":
        dev.ctrl_transfer(bm, req, val, idx, bytes.fromhex(op["payload"]),
                          timeout=timeout)
        return ""
    return bytes(dev.ctrl_transfer(bm, req, val, idx, op["len"],
                                   timeout=timeout)).hex()


def warm_shape(script, injected):
    """Windows warm init (neat-3x-backtoback.pcap scan2/scan3, 193 ops,
    identical): cold init MINUS the 17-op arm block, with gray300's
    0b09/8c framing moved before the first tables. injected scripts shed
    [5:22) (back to the original list); gray300 (inline arm) becomes
    [0:5) + [27:30) + [22:27) + [30:]. Returns the reordered list."""
    if injected:
        return script[:5] + script[22:]
    pre = script[27:30]
    want = [("out", "4004830000000200", "0b09"),
            ("out", "400c8c0010000100", "0a"),
            ("out", "400c8c0013000100", "0e")]
    got = [(o.get("op"), o.get("setup"), o.get("payload")) for o in pre]
    if got != want:
        raise InitWedgeError(f"warm framing moved: ops27-29={got}")
    return script[:5] + pre + script[22:27] + script[30:]


def replay_ctrl_range(dev, script, start=0, stop=None, verbose=False,
                      timeout=2000):
    """Replay script[start:stop] with one retry; warm-refused arm/
    telemetry ops are skipped (counted). Returns (n_in, n_out, n_skip)."""
    import usb.core as _uc
    import time as _t
    n_in = n_out = n_skip = 0
    ops = script[start:stop]
    i = 0
    while i < len(ops):
        op = ops[i]
        try:
            _xfer_once(dev, op, timeout)
        except Exception as e:
            if not isinstance(e, _uc.USBTimeoutError):
                raise
            _t.sleep(0.5)
            try:
                _xfer_once(dev, op, timeout)
            except Exception as e2:
                if (isinstance(e2, _uc.USBTimeoutError)
                        and _skippable(op)):
                    # Warm fw refusing already-configured/telemetry op.
                    # Probe-trio atomicity: if this is the 088f, also skip
                    # the following zeros + ACK when they match.
                    skip_n = 1
                    if (op["op"] == "out"
                            and op.get("payload") == "088f001004000000"):
                        nxt = ops[i + 1:i + 3] if i + 3 <= len(ops) else []
                        if (len(nxt) == 2 and nxt[0]["op"] == "bulk"
                                and nxt[0].get("data") == "00000000"
                                and nxt[1]["op"] == "in"
                                and nxt[1].get("setup")
                                == "c00c8e000b000100"):
                            skip_n = 3
                    n_skip += skip_n
                    if verbose:
                        print(f"  prefix op{start + i} skipped "
                              f"(warm-refused x{skip_n})", flush=True)
                    i += skip_n
                    continue
                raise
        if op["op"] == "in":
            n_in += 1
        else:
            n_out += 1
        _t.sleep(CTRL_PACE)
        i += 1
    if verbose:
        print(f"  ctrl replay [{start}:{stop if stop else len(script)}]: "
              f"{n_out} OUT + {n_in} IN + {n_skip} skipped")
    return n_in, n_out, n_skip


PAPER_STAGED = "3055"  # 400200 (2B) values: 3055 staged, 7055 empty,
# 3355 feeding, 7355->7055 paper-out, 0555 fresh-probe idle.


def verbose_note(args):
    return args.verbose


def boot_wait(dev, verbose=True, min_wait=5.0, quiet=8.0, max_wait=40.0):
    """Windows-faithful boot handshake (missing this = feed never arms).

    After SET_CONFIG the fw boots (lamp warmup, motor home) and posts
    8-byte status reports on EP0x81; the Windows driver polls them until
    they settle (cold r2: 16.. -> 06.. -> 20../27.. over ~19s, init at
    ~30s; warm: 04../2b.. over ~6.5s, init at ~10.6s) and only then
    starts vendor init. Slamming init at +0s is accepted but leaves the
    feed subsystem disarmed (static-line captures, no paper motion).
    Rule: phase 1 flushes stale image bytes (wedged runs); phase 2 polls
    8B status until QUIET seconds with no non-zero report (and at least
    MIN_WAIT elapsed), capped at MAX_WAIT.
    """
    import time as _t
    # NOTE: no clear_halt: Windows never sends CLEAR_FEATURE, and clearing
    # a healthy bulk endpoint desyncs toggles -> next bulk-framing 8200
    # wedges on warm reuse.
    for k in range(3):
        try:
            d = dev.read(EP_BULK_IN, 65536, timeout=500)
            if verbose:
                print(f"  boot flush {k}: discarded {len(d)} stale B")
        except Exception:
            break
    t0 = _t.monotonic()
    last_nz = t0
    n_nz = 0
    while True:
        now = _t.monotonic()
        el = now - t0
        if el >= min_wait and now - last_nz >= quiet:
            break
        if el >= max_wait:
            if verbose:
                print(f"  boot wait: cap {max_wait}s reached")
            break
        try:
            rep = bytes(dev.read(EP_BULK_IN, 8, timeout=1200))
        except Exception:
            continue
        if any(rep):
            last_nz = _t.monotonic()
            n_nz += 1
            if verbose:
                print(f"  boot status +{el:5.1f}s: {rep.hex()}")
    if verbose:
        print(f"  boot settled after {_t.monotonic()-t0:.1f}s "
              f"({n_nz} live reports)")


def replay_ctrl_rest_with_paper_wait(dev, script, start, verbose=False,
                                     timeout=2000, tries=30, delay=1.0,
                                     wait=True):
    """Replay script[start:] like Windows: the first three 400200 IN reads
    must return 3055 (paper staged). Retries each up to `tries` (~30 s total
    for the operator to feed the sheet); later 400200 reads (per-strip,
    expect 3355) are single-shot. Returns 'NO_DOCS' string on timeout."""
    import time
    import time as _t
    n_in = n_out = n4002 = 0
    inlog = []
    i_skip_until = -1
    for i, op in enumerate(script[start:], start):
        if i <= i_skip_until:
            continue
        if op["op"] == "bulk":
            assert op["len"] <= 64, op
            if verbose:
                print(f"  op{i} BULK OUT {op['len']}B {op['data'][:16]}...",
                      flush=True)
            try:
                dev.write(EP_BULK_OUT, bytes.fromhex(op["data"]),
                          timeout=timeout)
            except Exception as e:
                import usb.core as _ucb
                if (isinstance(e, _ucb.USBTimeoutError)
                        and op.get("data") == "00000000"):
                    if verbose:
                        print(f"  op{i} zeros refused: skipping",
                              flush=True)
                    continue
                raise
            n_out += 1
            _t.sleep(CTRL_PACE)
            continue
        bm, req, val, idx, wlen = parse_setup(op["setup"])
        if op["op"] == "out":
            if verbose:
                print(f"  op{i} CTRL OUT {op['setup']} "
                      f"{op['payload'][:24]}...", flush=True)
            try:
                dev.ctrl_transfer(bm, req, val, idx,
                                  bytes.fromhex(op["payload"]),
                                  timeout=timeout)
            except Exception as e:
                import usb.core as _uc
                if not isinstance(e, _uc.USBTimeoutError):
                    raise
                if verbose:
                    print(f"  op{i} retry after {e}", flush=True)
                _t.sleep(0.5)
                try:
                    dev.ctrl_transfer(bm, req, val, idx,
                                      bytes.fromhex(op["payload"]),
                                      timeout=timeout)
                except Exception as e2:
                    import usb.core as _uc2
                    # Warm-armed firmware refuses the cold-only 088f probe
                    # (Windows warm inits omit it): skip the trio (8200 +
                    # bulk zeros + ACK) plus its contextual follow-ups
                    # (a940/0600-probe/0b01) when they match, and continue.
                    if (isinstance(e2, _uc2.USBTimeoutError) and
                            op["payload"] == "088f001004000000"):
                        nxt = script[i + 1:i + 6]
                        follow = [
                            ("bulk", None, "00000000"),
                            ("in", "c00c8e000b000100", None),
                            ("out", "4004830000000200", "a940"),
                            ("out", "4004830000000600", "51043a003b00"),
                            ("out", "4004830000000200", "0b01"),
                        ]
                        ok = len(nxt) == 5
                        for _o, (_k, _s, _p) in zip(nxt, follow):
                            if _o["op"] != _k:
                                ok = False
                            elif _k == "bulk" and _o.get("data") != _p:
                                ok = False
                            elif _k == "in" and _o.get("setup") != _s:
                                ok = False
                            elif _k == "out" and (
                                    _o.get("setup") != _s
                                    or _o.get("payload") != _p):
                                ok = False
                        resume = i + 6 if ok else i + 1
                        if verbose:
                            print(f"  op{i} 088f refused: warm device, "
                                  f"skipping to op{resume}", flush=True)
                        return ("SKIP_PROBE", resume)
                    if (isinstance(e2, _uc2.USBTimeoutError)
                            and _skippable(op)):
                        if verbose:
                            print(f"  op{i} refused (skippable): skipping",
                                  flush=True)
                        continue
                    raise
            n_out += 1
            _t.sleep(CTRL_PACE)
            continue
        want_wait = (wait and op["setup"] == "c0048e0022400200"
                     and op["len"] == 2 and n4002 < 3)
        if want_wait:
            last = None
            for t in range(tries):
                try:
                    last = bytes(dev.ctrl_transfer(
                        bm, req, val, idx, 2, timeout=timeout)).hex()
                except Exception as e:
                    last = f"ERR {e}"
                if verbose:
                    print(f"  paper poll op{i} try{t}: 400200 -> {last}")
                if last == PAPER_STAGED:
                    break
                time.sleep(delay)
            if last != PAPER_STAGED:
                print(f"NO DOCUMENT: paper sensor reads {last} "
                      "(want 3055 staged; 7055 = empty). Feed paper fully "
                      "until it stops, power-cycle if repeated. "
                      "(SANE_STATUS_NO_DOCS, exit 2)")
                return "NO_DOCS"
            n4002 += 1
            n_in += 1
        else:
            if op["setup"] == "c0048e0022400200" and op["len"] == 2:
                n4002 += 1
            try:
                data = bytes(dev.ctrl_transfer(bm, req, val, idx, op["len"],
                                               timeout=timeout))
            except Exception as e:
                import usb.core as _uc3
                if not isinstance(e, _uc3.USBTimeoutError):
                    raise
                _t.sleep(0.5)
                try:
                    data = bytes(dev.ctrl_transfer(
                        bm, req, val, idx, op["len"], timeout=timeout))
                except Exception as e2:
                    if (isinstance(e2, _uc3.USBTimeoutError)
                            and _skippable(op)):
                        if verbose:
                            print(f"  op{i} IN refused (skippable): skipping",
                                  flush=True)
                        continue
                    raise
            inlog.append({"op": i, "setup": op["setup"], "data": data.hex()})
            n_in += 1
            _t.sleep(CTRL_PACE)
    if verbose:
        print(f"  ctrl replay [{start}:]: {n_out} OUT + {n_in} IN")
    return inlog


COLD_ARM_BLOCK = [
    # r2 ops 5-22 (cold boot only): feeder arm. Warm scripts skip this
    # whole block (feeder already armed); injecting it cold is what lets
    # the motor step. Payloads are pre-table boot commands (mode-generic).
    {"op": "out", "setup": "4004830000000200", "payload": "6e00"},
    {"op": "out", "setup": "4004830000000200", "payload": "a700"},
    {"op": "out", "setup": "4004830000000200", "payload": "6f00"},
    {"op": "out", "setup": "4004830000000200", "payload": "0650"},
    {"op": "out", "setup": "4004830000000200", "payload": "6c00"},
    {"op": "out", "setup": "4004830000000200", "payload": "6e02"},
    {"op": "out", "setup": "4004830000000200", "payload": "6c00"},
    {"op": "in", "setup": "c0048e0022410200", "len": 2},
    {"op": "out", "setup": "4004830000000200", "payload": "0b01"},
    {"op": "out", "setup": "400c8c0010000100", "payload": "0a"},
    {"op": "out", "setup": "400c8c0013000100", "payload": "0e"},
    {"op": "out", "setup": "4004820001000800",
     "payload": "088f001004000000"},
    {"op": "bulk", "len": 4, "data": "00000000"},
    {"op": "in", "setup": "c00c8e000b000100", "len": 1},
    {"op": "out", "setup": "4004830000000200", "payload": "a940"},
    {"op": "out", "setup": "4004830000000600", "payload": "51043a003b00"},
    {"op": "out", "setup": "4004830000000200", "payload": "0b01"},
]
_TELEMETRY_INS = ("c0048e0022014000", "c0048e0022404000",
                   "c0048e00227f4000", "c0048e0022be4000",
                   "c0048e0022fd0400", "c0048e0022410200",
                   "c0048e0022400300", "c0048e0022420400",
                   "c00c8e000b000100")


def _skippable(op):
    # Ops a warm-armed fw may refuse (already configured): skip-and-
    # continue instead of wedging. Paper 400200 is NEVER skippable;
    # table/config OUTs outside the arm block never are (cold integrity).
    # Cold firmware accepts all of these, so skips only ever fire warm
    # (or on flaky USB, which surfaces loudly in the log).
    if op["op"] == "bulk":
        return op.get("data") == "00000000"  # probe zeros only
    setup = op.get("setup", "")
    if op["op"] == "in":
        if setup == "c0048e0022400200":
            return False
        return setup in _TELEMETRY_INS
    if setup == "4004830000000200":
        return op.get("payload") in ("6e00", "a700", "6f00", "0650",
                                     "6c00", "6e02", "0b01", "a940")
    if setup == "400c8c0010000100":
        return op.get("payload") == "0a"
    if setup == "400c8c0013000100":
        return op.get("payload") == "0e"
    if setup == "4004830000000600":
        return op.get("payload") == "51043a003b00"
    if setup == "4004820001000800":
        return op.get("payload") == "088f001004000000"
    return False


COLD_ARM_PREFIX_INS = (
    "c0048e0022014000", "c0048e0022404000", "c0048e00227f4000",
    "c0048e0022be4000", "c0048e0022fd0400",
)


def cold_arm_script(script):
    """Insert the r2 cold-arm block into warm-derived scripts (150/600/
    color), which skip it. Returns (script, armed?). Cold scripts
    (inline bulk probe) are returned untouched."""
    if any(o["op"] == "bulk" for o in script):
        return script, False
    if (len(script) >= 6
            and all(script[k]["op"] == "in"
                    and script[k]["setup"] == COLD_ARM_PREFIX_INS[k]
                    for k in range(5))
            and not (script[5]["op"] == "out"
                     and script[5].get("payload") == "6e00")):
        return (script[:5] + [dict(o) for o in COLD_ARM_BLOCK]
                + script[5:], True)
    return script, False
def split_at_second_8c(script):
    """Index just after the 2nd 8c OUT (first 400c8c0013000100) -- the
    cold-probe insertion point (matches r2 pkt62->64)."""
    for i, op in enumerate(script):
        if op["op"] == "out" and op["setup"] == "400c8c0013000100":
            return i + 1
    raise ValueError("8c marker not found in ctrl script")


def feeder_probe(dev, verbose=False, timeout=2000):
    """Cold feeder init (r2 pkt64-69, also empty-error frame 55):
    8200(088f) + bulk OUT 4B 00000000 + IN 0b000100 (ACK, always 00).
    Arms the paper path on a fresh power-up; warm-session captures
    (r1) lack it because an earlier scan already armed the feeder."""
    import usb.core
    dev.ctrl_transfer(0x40, 0x04, 0x0082, 0x0001,
                       bytes.fromhex("088f001004000000"), timeout=timeout)
    dev.write(EP_BULK_OUT, b"\x00\x00\x00\x00", timeout=timeout)
    ack = bytes(dev.ctrl_transfer(0xC0, 0x0C, 0x008E, 0x000B, 1,
                                  timeout=timeout))
    if verbose:
        print(f"  feeder probe ACK: {ack.hex()}")
    return ack.hex()


def replay_full_pcap(dev, mode, dpi, verbose=False):
    """Full pcap replay for live scans (fixes rollers not feeding).

    Replays the exact vendor/bulk sequence from the captured Windows pcap:
    - Bulk OUT calibration with vendor 8200 framing BEFORE every chunk
      (pcap: 004001 precedes the first cal block too)
    - Post-bulk vendor sequence (per-mode 2e00/1000 + small 8300s + INs)
    - Image loop handled by bulk_in_image_full() with per-mode img8200.
    """
    cfg = MODE_CFG[(mode, dpi)]
    splits = cfg["splits"]
    blob = (HERE / cfg["blob"]).read_bytes()
    assert len(blob) == sum(splits), (len(blob), sum(splits))
    b8200 = cfg["b8200"]
    assert len(b8200) == len(splits), (len(b8200), len(splits))
    import time as _t2
    _t2.sleep(2.0)  # settle after init (lamp/motor spin-up window)

    if cfg.get("is600"):
        _poll600(dev, verbose=verbose)

    def _frame_retry(pay, tag):
        for attempt in range(4):
            try:
                dev.ctrl_transfer(0x40, 0x04, 0x0082, 0x0001,
                                   bytes.fromhex(pay), timeout=5000)
                break
            except Exception as e:
                import time as _t
                if verbose:
                    print(f"  VENDOR 8200 {tag} try{attempt}: {e}",
                          flush=True)
                if attempt == 3:
                    raise
                _t.sleep(0.5)
        if verbose:
            print(f"  VENDOR 8200 {tag}: {pay}", flush=True)

    def _vout(setup, pay):
        bm, req, val, idx, wlen = parse_setup(setup)
        dev.ctrl_transfer(bm, req, val, idx, bytes.fromhex(pay),
                          timeout=2000)
        _t2.sleep(CTRL_PACE)

    def _vin(setup, ln, tag="tail"):
        bm, req, val, idx, wlen = parse_setup(setup)
        data = bytes(dev.ctrl_transfer(bm, req, val, idx, ln, timeout=2000))
        if verbose:
            print(f"  {tag} {setup} -> {data.hex()[:48]}...", flush=True)
        _t2.sleep(CTRL_PACE)
        return data.hex()

    def _bulk(chunk, tag):
        dev.write(EP_BULK_OUT, chunk, timeout=5000)
        if verbose:
            print(f"  BULK OUT {tag}: {len(chunk)} B")
        _t2.sleep(BULK_PACE)

    off = 0
    # Cal + command blocks (first 6 splits). The first framing is the
    # init-JSON tail op (skip i==0), except gray600 (frame_first).
    for i in range(6):
        ln = splits[i]
        if i > 0 or cfg.get("frame_first"):
            _frame_retry(b8200[i], f"before bulk {i}")
        _bulk(blob[off:off + ln], str(i))
        off += ln
    # Ordered tail region (previously 13 missing OUTs + 3 INs).
    _vin("c0048e0022410200", 2)
    _vin("c00c8e001c000100", 1)
    _vin("c0048e0022480400", 4)
    _vout("4004830000002800", cfg["tail2800"])
    _vout("4004830000000a00", cfg["tail0a00"])
    _vout("4004830000000200", "1000")
    _vout("4004830000000200", "9d00")
    _frame_retry(b8200[6], "before BULK32")
    _bulk(blob[off:off + splits[6]], "6")
    off += splits[6]
    if cfg.get("extra_tails"):
        framing_pay, bulk_hex = cfg["extra_tails"][0]
        _frame_retry(framing_pay, "before tail8")
        _bulk(bytes.fromhex(bulk_hex), "tail8")
    else:
        _frame_retry(b8200[7], "before BULK8")
        _bulk(blob[off:off + splits[7]], "7")
        off += splits[7]
    _vout("4004830000000600", "3d003e003f01")
    for t0400 in cfg["tail0400"]:
        _vout("4004830000000400", t0400)
    for small in ("0d01", "0d00", "0d10", "6b81", "6320"):
        _vout("4004830000000200", small)
    if cfg.get("extra_tails"):
        framing_pay, bulk_hex = cfg["extra_tails"][1]
        _frame_retry(framing_pay, "before tail2")
        _bulk(bytes.fromhex(bulk_hex), "tail2")
    else:
        _frame_retry(b8200[8], "before BULK2")
        _bulk(blob[off:off + splits[8]], "8")
        off += splits[8]
    if verbose:
        print(f"  bulk OUT done {off}B blob + tails")
    # Post-bulk motor-start sequence (2e00 ... + image 8200).
    post_inlog = []
    post_seq = [
        ("out", "4004830000002e00", cfg["post2e"]),
        ("out", "4004830000000200", "0f01"),
        ("out", "4004830000000200", "6b01"),
        ("in", "c0048e0022400300", 3),
        ("out", "4004830000000200", "0810"),
        ("out", "4004830000001000", cfg["post1000"]),
        ("out", "4004830000000200", "2010"),
        ("out", "4004830000000200", "9f00"),
        ("out", "4004830000000200", "0250"),
        ("out", "4004830000000200", "0850"),
        ("out", "4004830000000200", "a800"),
        ("out", "4004830000000200", "01a1"),
        ("out", "4004830000000200", "0fff"),
        ("out", "4004830000000200", "01e1"),
        ("in", "c0048e0022014000", 64),
        ("in", "c0048e0022404000", 64),
        ("in", "c0048e00227f4000", 64),
        ("in", "c0048e0022be4000", 64),
        ("in", "c0048e0022fd0400", 4),
        ("in", "c0048e0022410200", 2),
        ("in", "c0048e0022400300", 3),
        ("in", "c0048e0022420400", 4),
        ("out", "4004820000000800", cfg["img8200"]),
    ]
    for typ, setup, val in post_seq:
        bm, req, v, idx, wlen = parse_setup(setup)
        if typ == "out":
            dev.ctrl_transfer(bm, req, v, idx, bytes.fromhex(val),
                              timeout=2000)
        else:
            data = bytes(dev.ctrl_transfer(bm, req, v, idx, val,
                                           timeout=2000))
            post_inlog.append({"setup": setup, "data": data.hex()})
            if verbose:
                print(f"  post {setup} -> {data.hex()[:48]}...", flush=True)
        _t2.sleep(CTRL_PACE)
    if verbose:
        print("  post-bulk vendors done")
    return post_inlog


def _poll600(dev, verbose=False):
    """600-DPI pre-cal sensor sweep (pcap ops ~208-8738, 704 cycles).

    Header once, then 704x [8B row-address OUT | 2B OUT | 2B IN | 256B
    IN]. Framer setups: bulk-OUT = 4004820001000800, bulk-IN =
    4004820000000800. Addresses are open-loop (k*0x20, no content
    feedback), so generate them; IN data is discarded. No extra pacing
    (natural rate ~= measured 16ms/cycle).
    """
    import usb.core as _uc

    def _oframer(pay):
        dev.ctrl_transfer(0x40, 0x04, 0x0082, 0x0001,
                          bytes.fromhex(pay), timeout=5000)

    def _iframer(pay):
        dev.ctrl_transfer(0x40, 0x04, 0x0082, 0x0000,
                          bytes.fromhex(pay), timeout=5000)

    def _out(framer_pay, data):
        _oframer(framer_pay)
        dev.write(EP_BULK_OUT, bytes(data), timeout=5000)

    def _in(framer_pay, n):
        _iframer(framer_pay)
        got = bytearray()
        while len(got) < n:
            try:
                chunk = dev.read(EP_BULK_IN, n - len(got), timeout=5000)
            except _uc.USBTimeoutError:
                break
            if len(chunk) == 0:
                break
            got += bytes(chunk)
        if len(got) != n and verbose:
            print(f"  poll600: short IN ({len(got)}/{n})", flush=True)
        return bytes(got)

    # Header: the init script's last op already sent framer
    # 0000000302000000, so complete it first, then the rest verbatim.
    dev.write(EP_BULK_OUT, bytes.fromhex("0400"), timeout=5000)
    for framer_pay, data in (("0200000302000000", bytes.fromhex("0100")),
                             ("0800000302000000", bytes.fromhex("0208")),
                             ("0a00000302000000", bytes.fromhex("9f9f")),
                             ("0c00000302000000", bytes.fromhex("9f9f")),
                             ("0400000302000000", bytes.fromhex("1000"))):
        _out(framer_pay, data)
    _in("0600000302000000", 2)
    _out("0600000302000000", bytes.fromhex("0100"))
    for _ in range(3):
        _in("0e00000302000000", 2)
    for k in range(704):
        addr = k * 0x20
        pay8 = bytes((0x01, 0x00, 0x0f, 0x20, addr & 0xff,
                      (addr >> 8) & 0xff, 0x02, 0x03))
        _out("0600000308000000", pay8)
        _out("0400000302000000", bytes.fromhex("1008"))
        _in("0600000302000000", 2)
        _in("0e00000300010000", 256)
        if verbose and (k < 2 or k % 100 == 0):
            print(f"  poll600 cycle {k}/704...", flush=True)
    if verbose:
        print("  poll600 sweep done", flush=True)


CLOSE_TBL4000 = (
    "01a002700392041005000650081009000a000c000b090d001000110012001300"
    "1400150016001701180419e01a261b001c001d041e101f012010210422502350",
    "24042500260027002c022d582e802f8030003114322733ec343c350036403700"
    "3817396f3d003e003f015211530254055508560b570e588b59005ac05e885f01",
    "6600673f683f69016a046b016e6f6c616f006d00700471067207730874007500"
    "76007700780079fc7a037bff7cff87009d049e009f00a20fa800a940ab30ad00",
)
CLOSE_0800 = "ae3fb800bd00be00"
CLOSE_3600 = (
    "51013a003b3551023a003b8051033a003b0451203a003b8051213a003b805122"
    "3a003b8051283a003bbb51293a003b4b512a3a003b4b"
)


def close_scan(dev, mode, dpi, verbose=False, timeout=1500):
    """Windows-faithful end-of-scan ritual (verbatim all modes 150/300/
    color; 600 uses only the short tail -- its pcap has no 0400 rite).
    Best-effort: never fails the scan (image already captured); logs.
    Without it the fw holds the scan context and the next init wedges
    at the first bulk-framer."""
    import usb.core as _uc
    cfg = MODE_CFG[(mode, dpi)]
    seq = []

    def OUT(setup, pay):
        seq.append(("out", setup, pay))

    def IN(setup, ln):
        seq.append(("in", setup, ln))

    if not cfg.get("is600"):
        OUT("4004820000000800", "0000000104000000")
        seq.append(("bin4", None, None))
    for pay in ("0250", "20ff") if not cfg.get("is600") else ():
        OUT("4004830000000200", pay)
    if not cfg.get("is600"):
        OUT("4004830000000600", "350036003700")
        OUT("4004830000000200", "01e0")
        IN("c0048e0022410200", 2)
        IN("c0048e0022480400", 4)
        OUT("4004830000000200", "0a00")
        OUT("4004830000000200", "01a0")
        for setup, ln in (("c0048e0022014000", 64),
                          ("c0048e0022404000", 64),
                          ("c0048e00227f4000", 64),
                          ("c0048e0022be4000", 64),
                          ("c0048e0022fd0400", 4),
                          ("c0048e0022410200", 2)):
            IN(setup, ln)
        IN("c0048e00224b0400", 4)
        for setup, ln in (("c0048e0022014000", 64),
                          ("c0048e0022404000", 64),
                          ("c0048e00227f4000", 64),
                          ("c0048e0022be4000", 64),
                          ("c0048e0022fd0400", 4),
                          ("c0048e0022410200", 2)):
            IN(setup, ln)
        for pay in ("6e6f", "7e00", "0312", "0392", "6f00", "6d1f",
                    "6b01"):
            OUT("4004830000000200", pay)
        OUT("4004830000000200", "0b09")
        OUT("400c8c0010000100", "0a")
        OUT("400c8c0013000100", "0e")
        for t in CLOSE_TBL4000:
            OUT("4004830000004000", t)
        OUT("4004830000000800", CLOSE_0800)
        OUT("4004830000003600", CLOSE_3600)
        IN("c004840006e20400", 4)
        for setup, ln in (("c0048e0022014000", 64),
                          ("c0048e0022404000", 64),
                          ("c0048e00227f4000", 64),
                          ("c0048e0022be4000", 64),
                          ("c0048e0022fd0400", 4),
                          ("c0048e0022410200", 2),
                          ("c0048e00220a0200", 2)):
            IN(setup, ln)
    OUT("4004830000000200", "0a20")
    IN("c0048e0022400200", 2)
    for pay in ("0312", "0392", "6f00", "6d1f", "6b01"):
        OUT("4004830000000200", pay)
    for typ, setup, val in seq:
        try:
            if typ == "out":
                bm, req, v, idx, wlen = parse_setup(setup)
                dev.ctrl_transfer(bm, req, v, idx,
                                  bytes.fromhex(val), timeout=timeout)
            elif typ == "in":
                bm, req, v, idx, wlen = parse_setup(setup)
                data = bytes(dev.ctrl_transfer(bm, req, v, idx, val,
                                               timeout=timeout))
                if verbose:
                    print(f"  close {setup} -> {data.hex()[:24]}",
                          flush=True)
            else:  # bin4
                dev.ctrl_transfer(0x40, 0x04, 0x0082, 0x0000,
                                  bytes.fromhex("0000000104000000"),
                                  timeout=timeout)
                got = bytes(dev.read(EP_BULK_IN, 4, timeout=timeout))
                if verbose:
                    print(f"  close BIN4 -> {got.hex()}", flush=True)
        except Exception as e:
            if verbose:
                print(f"  close note ({typ} {setup}): {e}", flush=True)
    if verbose:
        print("  close ritual done", flush=True)


def bulk_in_image_full(dev, mode, dpi, verbose=False, timeout=3000,
                       max_bytes=64 * 1024 * 1024):
    """Bulk IN image loop with per-strip vendor IN/OUT (pcap strip structure).

    Each 64K read (≈ one short-terminated strip) is framed by 7 vendor
    INs (400200/0122/4022/7f22/be22/fd04/4102) + per-mode image 8200 OUT.
    Ends on bulk idle timeout (paper out). Safety cap aborts a no-feed
    zero stream instead of filling disk.
    """
    import usb.core
    cfg = MODE_CFG[(mode, dpi)]
    strip_vendors = [
        ("in", "c0048e0022400200", 2),
        ("in", "c0048e0022014000", 64),
        ("in", "c0048e0022404000", 64),
        ("in", "c0048e00227f4000", 64),
        ("in", "c0048e0022be4000", 64),
        ("in", "c0048e0022fd0400", 4),
        ("in", "c0048e0022410200", 2),
        ("out", "4004820000000800", cfg["img8200"]),
    ]
    PAPER_OUT = ("7355", "7055", "7155", "3955")
    # 7355 = trailing edge at sensor (remainder still streams);
    # 7055/7155 = scan closed (fw idles, serves stale -- stop at once);
    # 3955 = 150-DPI feed fault (terminal).
    import time as _t
    cycle = cfg.get("cycle", 0.090)
    raw = bytearray()
    n = 0
    paper_out_at = None
    dark_streak = 0
    ended = None
    # First bulk-IN touch: the fw may have a ≤4B status word queued
    # (seen warm without boot-wait) or already flood image. Use a full
    # 64K buffer — anything smaller OVERFLOWs on the first 512B packet
    # when image floods instantly (proven c6warm). ≤4B dropped (not
    # image); anything bigger is strip 1, consumed alone below.
    pending = b""
    try:
        pre = bytes(dev.read(EP_BULK_IN, 65536, timeout=300))
    except usb.core.USBTimeoutError:
        pre = b""
    if 0 < len(pre) <= 4:
        if verbose:
            print(f"  pre-image status {pre.hex()} dropped")
    elif pre:
        pending = pre
        if verbose:
            print(f"  pre-image {len(pre)}B kept as strip 1")
    while len(raw) < max_bytes and ended is None:
        t_strip = _t.monotonic()
        # 64 KiB reads: the fw short-packets each strip (~63700 B), so a
        # 64K URB completes on the short packet and self-synchronizes.
        # Exact-size URBs overflow when host/fw bulk toggles disagree
        # (warm runs without set_configuration, proven c3warm) while the
        # backend's 64K loop is live-proven (scan.pnm via scanimage).
        if pending:
            chunk = pending
            pending = b""
        else:
            try:
                chunk = bytes(dev.read(EP_BULK_IN, 65536, timeout=timeout))
            except usb.core.USBTimeoutError:
                if verbose:
                    print(f"  strip {n}: idle timeout, end of image")
                ended = "idle"
                break
        if len(chunk) == 0:
            ended = "short"
            break
        raw += chunk
        n += 1
        if verbose and (n <= 3 or n % 10 == 0):
            print(f"  BULK IN: {len(raw)} B in {n} reads... "
                  f"chunk head={chunk[:8].hex()} len={len(chunk)}")
        # Per-strip vendors; watch 400200 for paper-out (7355/7055) and
        # log it (3355 = feeding). Values never reaching 3355 means the
        # motor never stepped even though transfers succeed.
        paper_status = None
        detail = (n < 3)
        for typ, setup, val in strip_vendors:
            bm, req, v, idx, wlen = parse_setup(setup)
            try:
                if typ == "out":
                    dev.ctrl_transfer(bm, req, v, idx,
                                      bytes.fromhex(val), timeout=800)
                else:
                    resp = bytes(dev.ctrl_transfer(
                        bm, req, v, idx, val, timeout=800)).hex()
                    if setup == "c0048e0022400200":
                        paper_status = resp
                    if detail:
                        print(f"  strip {n} {setup[4:8]} -> "
                              f"{resp[:48]}...", flush=True)
            except Exception as e:
                if detail:
                    print(f"  strip {n} {setup[4:8]} ERR {e}", flush=True)
        if verbose and (n <= 3 or n % 20 == 0 or
                        paper_status in PAPER_OUT):
            print(f"  strip {n}: 400200 -> {paper_status}")
        _el = _t.monotonic() - t_strip
        if _el < cycle:
            _t.sleep(cycle - _el)
        # Sensor sits ~1" upstream of the head: 7355 = trailing edge at
        # the SENSOR, but ~300 rows are still under the head. Keep the
        # normal framed loop going (fw streams the remainder, then idles
        # -> short read ends it). Stop only after 40 post-out strips.
        if paper_status in PAPER_OUT:
            if paper_out_at is None:
                paper_out_at = n
                if verbose:
                    print(f"  paper-out at strip {n} ({paper_status}), "
                          "reading head-clearing remainder...")
            elif n - paper_out_at >= 64:
                if verbose:
                    print(f"  post-paper-out cap, end of image...")
                ended = "paper-out"
                break
        # Content end: 3 consecutive lid-dark strips after paper-out =
        # trailing edge fully past the head (the 7155-closed fw keeps
        # serving stale brights; darkness is the true end).
        if paper_out_at is not None and ended is None:
            _m = sum(chunk[::7]) / (len(chunk) // 7 + 1)
            if _m < 50:
                dark_streak += 1
                if dark_streak >= 3:
                    if verbose:
                        print(f"  lid-dark x3 at strip {n}, end of image")
                    ended = "paper-out"
                    break
            else:
                dark_streak = 0
    if len(raw) > 0:
        # Drain the fw's end-of-scan queue with plain reads (no 8200s).
        # MUST drain until clean: leftover bytes back-pressure the fw and
        # it refuses the next scan's first bulk-framer (warm op207 wedge).
        # Discarded, never appended: post-end bytes are lid-dark repeats
        # or 7155 stale brights, and appending shifts width math (rem).
        # Exit on 3 consecutive timeouts (cap 64 reads; stale-infinite
        # servers stop there). Short timeout: residue arrives promptly.
        _miss = 0
        _drained = 0
        for _ in range(64):
            try:
                tail = dev.read(EP_BULK_IN, 65536, timeout=800)
            except Exception:
                _miss += 1
                if _miss >= 3:
                    break
                continue
            if len(tail) == 0:
                _miss += 1
                if _miss >= 3:
                    break
                continue
            _miss = 0
            _drained += len(tail)
        if verbose:
            print(f"  drain: discarded {_drained} B")
    # End-of-scan close ritual runs in run_scan() (post-image only).
    if verbose:
        print(f"  bulk IN full done: {len(raw)} B in {n} strips "
              f"(end={ended})")
    return bytes(raw)


def probe_empty_feeder(dev, verbose=False, timeout=2000):
    """Send 4B 00000000 empty probe (frame 55 in neat-empty-error.pcap).
    Returns True if probe accepted (device will then respond with control-only
    and zero image). Used to distinguish NO_DOCS from hard stall."""
    import usb.core
    try:
        dev.clear_halt(EP_BULK_OUT)
        dev.clear_halt(EP_BULK_IN)
    except Exception:
        pass
    try:
        if verbose:
            print("  probing empty feeder (00000000)...")
        dev.write(EP_BULK_OUT, b"\x00\x00\x00\x00", timeout=timeout)
        if verbose:
            print("  probe write ok (device in empty-feeder state)")
        return True
    except usb.core.USBTimeoutError:
        if verbose:
            print("  probe timeout (not empty path)")
        return False
    except Exception as e:
        if verbose:
            print(f"  probe err {e}")
        return False


def bulk_in_image(dev, verbose=False, chunk=65536, timeout=3000):
    import usb.core

    raw = bytearray()
    n = 0
    while True:
        try:
            data = dev.read(EP_BULK_IN, chunk, timeout=timeout)
            raw += bytes(data)
            n += 1
            if verbose and (n % 20 == 0):
                print(f"  BULK IN: {len(raw)} B in {n} reads...")
        except usb.core.USBTimeoutError:
            break
    if verbose:
        print(f"  bulk IN done: {len(raw)} B in {n} reads (timeout {timeout}ms)")
    return bytes(raw)


def auto_levels_lut(raw, floor_gap=25):
    """Otsu-split ink/background -> LUT mapping bg mean to 235, ink mean
    to 10. Raw CIS reads are dark (paper ~140 @300, ~55 @150); without
    the Windows cal-table math this stretch recovers readable pages.
    Returns None when contrast is too low (blank/lid frames)."""
    hist = [0] * 256
    for b in raw:
        hist[b] += 1
    tot = len(raw)
    sum_all = sum(i * hist[i] for i in range(256))
    sum_b = 0
    w_b = 0
    best_t = 0
    best_var = -1.0
    for t in range(256):
        w_b += hist[t]
        if w_b == 0:
            continue
        w_f = tot - w_b
        if w_f == 0:
            break
        sum_b += t * hist[t]
        m_b = sum_b / w_b
        m_f = (sum_all - sum_b) / w_f
        var = w_b * w_f * (m_b - m_f) ** 2
        if var > best_var:
            best_var = var
            best_t = t
    lo = sum(i * hist[i] for i in range(best_t + 1))
    n_lo = sum(hist[:best_t + 1])
    hi = sum(i * hist[i] for i in range(best_t + 1, 256))
    n_hi = tot - n_lo
    if n_lo == 0 or n_hi == 0:
        return None
    black, white = lo / n_lo, hi / n_hi
    if white - black < floor_gap:
        return None
    scale = 225.0 / (white - black)
    return bytes(max(0, min(255, int((v - black) * scale + 10)))
                 for v in range(256))


def render_gray(raw, width, out_path, auto_levels=True):
    from PIL import Image

    h = len(raw) // width
    rem = len(raw) % width
    img = Image.frombytes("L", (width, h), bytes(raw[:width * h]))
    if auto_levels:
        lut = auto_levels_lut(raw[:width * h])
        if lut is not None:
            img = img.point(lut)
    img.save(out_path)
    return h, rem


def render_color(raw, width_px, out_path, auto_levels=True):
    """Line-sequential RGB triplets (verified live color300: every 3
    consecutive width_px lines = R,G,B; per-line channel means cycle
    mod-3 through all 24 strip lines)."""
    from PIL import Image

    rows = len(raw) // width_px
    rem = len(raw) % width_px
    raw = raw[:rows * width_px]
    groups = rows // 3
    planes = [bytearray() for _ in range(3)]
    for g in range(groups):
        base = g * 3 * width_px
        for c in range(3):
            planes[c] += raw[base + c * width_px:base + (c + 1) * width_px]
    ch = []
    for c in range(3):
        im = Image.frombytes("L", (width_px, groups), bytes(planes[c]))
        if auto_levels:
            lut = auto_levels_lut(bytes(planes[c]))
            if lut is not None:
                im = im.point(lut)
        ch.append(im)
    img = Image.merge("RGB", ch)
    img.save(out_path)
    return groups, rows % 3 or rem


class InitWedgeError(Exception):
    """Init-phase USB failure before any paper fed (safe to retry)."""


def usb_reopen_pause(verbose=True):
    """Best-effort pause letting a wedged firmware settle. NOTE: no USB
    port reset here: resetting a bulk-confused NM-1000 drops it off the
    bus entirely (proven twice); a clean re-open is safer."""
    import time as _t
    _t.sleep(2)
    try:
        import usb.core
        return usb.core.find(idVendor=VID, idProduct=PID) is not None
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description="Neat NM-1000 Linux scanner driver v1")
    ap.add_argument("--mode", choices=["gray", "color"], default="gray")
    ap.add_argument("--dpi", type=int, choices=[150, 300, 600], default=300)
    ap.add_argument("--raw", default="scan.raw", help="raw output path")
    ap.add_argument("--out", default="scan.png", help="rendered PNG path")
    ap.add_argument("--ctrl-timeout", type=int, default=2000)
    ap.add_argument("--bulk-timeout", type=int, default=5000)
    ap.add_argument("--in-timeout", type=int, default=3000,
                    help="bulk IN idle timeout ms (end of scan)")
    ap.add_argument("--in-chunk", type=int, default=65536)
    ap.add_argument("--skip-ctrl", action="store_true",
                    help="skip EP0 init (bulk-only, like replay_nm1000.py)")
    ap.add_argument("--skip-bulk-out", action="store_true")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse scripts/blobs only, no USB")
    ap.add_argument("--no-paper-poll", action="store_true",
                    help="skip the 400200 paper-wait (default: wait up to "
                    "--paper-timeout s for paper staged)")
    ap.add_argument("--no-cold-arm", action="store_true",
                    help="skip injecting the r2 cold-arm block into "
                    "warm-derived scripts (default: inject; needed so a "
                    "cold device steps the motor)")
    ap.add_argument("--no-boot-wait", action="store_true",
                    help="skip the EP81 boot-status handshake (default: wait "
                    "for boot to settle; skipping disarms the feed motor)")
    ap.add_argument("--no-set-config", action="store_true",
                    help="skip set_configuration(1) on open (default: send; "
                    "Windows sends it once per plug, never between warm "
                    "scans — skipping may help warm reuse)")
    ap.add_argument("--stop-after-post-cal", action="store_true",
                    help="stop after post-calibration reads (fast protocol "
                    "check, no image)")
    ap.add_argument("--paper-timeout", type=int, default=10,
                    help="seconds to wait per staged-400200 read (3 reads, "
                    "~30 s total) before NO_DOCS (default 10)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if (args.mode, args.dpi) not in MODE_CFG:
        sys.exit(f"unsupported mode/DPI: {(args.mode, args.dpi)} "
                 f"(have {sorted(MODE_CFG)})")

    key = (args.mode, args.dpi)
    cfg = MODE_CFG[key]
    script = load_ctrl_script(*key)
    if args.dry_run and not args.skip_ctrl and not args.no_cold_arm:
        script, _armed = cold_arm_script(script)
    blob_path = HERE / cfg["blob"]
    blob = blob_path.read_bytes()
    n_tails = len(cfg.get("extra_tails", ()))
    expect = sum(cfg["splits"])
    print(f"mode={args.mode} dpi={args.dpi} "
          f"ctrl_ops={len(script)} bulk_blob={len(blob)}B ({blob_path.name})"
          f"{' +tails' if n_tails else ''}"
          f"{' EXPERIMENTAL' if cfg.get('experimental') else ''}")
    if args.dry_run:
        assert len(blob) == expect, (len(blob), expect)
        split = split_at_second_8c(script)
        print(f"dry-run OK (split_at_8c={split}, "
              f"img8200={cfg['img8200']}, post2e={cfg['post2e'][:16]}...)")
        return 0

    try:
        import usb.core
        import usb.util
    except ImportError:
        sys.exit("pyusb not found: pip install --user pyusb (see README)")
    try:
        return run_scan(args, cfg, key, script)
    except InitWedgeError as e:
        print(f"init wedge ({e}); re-opening + one retry (no reset)...")
        if usb_reopen_pause(verbose=args.verbose):
            try:
                return run_scan(args, cfg, key, script)
            except InitWedgeError as e2:
                print(f"retry failed ({e2})")
        print("POWER-CYCLE the scanner (unplug 30s), re-stage paper, retry.")
        return 1


def run_scan(args, cfg, key, script):
    import usb.core
    import usb.util
    dev = None
    try:
        dev = usb.core.find(idVendor=VID, idProduct=PID)
        if dev is None:
            sys.exit("scanner not found (1f44:0001). "
                     "Check cable/power/udev rules (see 60-neat-nm1000.rules).")
        try:
            if dev.is_kernel_driver_active(0):
                dev.detach_kernel_driver(0)
        except Exception:
            pass
        if args.no_set_config:
            print("skipping set_configuration (--no-set-config)...")
        else:
            try:
                dev.set_configuration(1)
            except usb.core.USBError as e:
                raise InitWedgeError(f"set_configuration failed ({e})")
        usb.util.claim_interface(dev, 0)
        print("claimed 1f44:0001 IF0")
        if not args.skip_ctrl and not args.no_boot_wait:
            print("boot handshake: draining status until settled "
                  "(feeds only arm after this)...")
            boot_wait(dev, verbose=args.verbose)

        # Cold-arm block: injected into warm-derived scripts. Whether the
        # fw needs it is probed live (Windows warm inits omit it): a cold
        # fw accepts the probe and arms; a warm fw refuses fast and the
        # block is skipped whole. Flaky-USB skips on a cold run surface
        # loudly in the log (probe + per-op refusal lines).
        if not args.skip_ctrl and not args.no_cold_arm:
            script, armed = cold_arm_script(script)
            if armed and verbose_note(args):
                print(f"cold-arm injected ({len(COLD_ARM_BLOCK)} ops)")
        else:
            armed = False
        # Arm block sits at script[5:22] whenever present — injected or
        # cold-capture inline (6e00 opener + 00000000 probe bulk nearby).
        # Windows warm inits omit it, so its presence is probed live.
        has_arm = (
            len(script) > 22
            and script[5].get("op") == "out"
            and script[5].get("payload") == "6e00"
            and any(o.get("op") == "bulk" and o.get("data") == "00000000"
                    for o in script[5:30])
        )
        if not args.skip_ctrl:
            # Init prefix + paper-wait rest. When the script carries the
            # 17-op arm block at [5:22), probe the 6e00 opener once
            # (500 ms, no retry): accepted = cold (send it all), refused =
            # warm (reshape to the verbatim Windows warm init and replay
            # that). has_arm covers injected and cold-capture inline alike.
            import usb.core as _ucp
            state = "cold"
            if has_arm:
                print("replaying EP0 init prefix (probing arm)...")
                replay_ctrl_range(dev, script, 0, 5, verbose=args.verbose,
                                  timeout=args.ctrl_timeout)
                try:
                    _xfer_once(dev, script[5], 500)
                except Exception as e:
                    if not isinstance(e, _ucp.USBTimeoutError):
                        raise
                    print("feeder state: warm (Windows warm shape).")
                    script = warm_shape(script, armed)
                    state = "warm"
                else:
                    print("feeder state: cold (full init).")
            split = split_at_second_8c(script)
            if has_arm and state == "cold":
                print(f"replaying EP0 init block [6:{split})...")
                replay_ctrl_range(dev, script, 6, split,
                                  verbose=args.verbose,
                                  timeout=args.ctrl_timeout)
                rest_at = split
            elif has_arm:
                print(f"replaying EP0 init prefix [0:{split})...")
                replay_ctrl_range(dev, script, 0, split,
                                  verbose=args.verbose,
                                  timeout=args.ctrl_timeout)
                rest_at = split
            else:
                print(f"replaying EP0 init prefix ({split} ops)...")
                replay_ctrl_range(dev, script, 0, split,
                                  verbose=args.verbose,
                                  timeout=args.ctrl_timeout)
                rest_at = split
            if not args.no_paper_poll:
                print("replaying EP0 init rest with paper-wait on the first "
                      "three 400200 reads (feed paper fully now)...")
            rest = replay_ctrl_rest_with_paper_wait(
                dev, script, rest_at, verbose=args.verbose,
                timeout=args.ctrl_timeout, tries=args.paper_timeout, delay=1.0,
                wait=not args.no_paper_poll)
            if isinstance(rest, tuple) and rest[0] == "SKIP_PROBE":
                print(f"warm fallback: resuming init at op{rest[1]}...")
                rest2 = replay_ctrl_rest_with_paper_wait(
                    dev, script, rest[1], verbose=args.verbose,
                    timeout=args.ctrl_timeout, tries=args.paper_timeout,
                    delay=1.0, wait=not args.no_paper_poll)
                rest = rest2
            if rest == "NO_DOCS":
                return 2
            print("paper staged (3055).")
            inlog_path = args.raw + ".inlog.json"
            with open(inlog_path, "w") as f:
                json.dump(rest, f)
            print(f"saved {len(rest)} IN responses -> {inlog_path}")
        else:
            print("skipping EP0 init (--skip-ctrl)")

        # Live scan: framed bulk OUT (8200 before EVERY chunk incl. first) +
        # per-mode post-bulk vendors, then exact-size strip loop.
        if not args.skip_bulk_out:
            print("replaying bulk OUT calibration (framed, per-mode)...")
            try:
                post_inlog = replay_full_pcap(dev, args.mode, args.dpi,
                                              verbose=args.verbose)
            except Exception as e:
                import usb.core as _uc
                if isinstance(e, _uc.USBTimeoutError):
                    raise InitWedgeError(f"bulk OUT stalled ({e})")
                raise
            if args.stop_after_post_cal:
                import json as _js
                pp = args.raw + ".postinlog.json"
                with open(pp, "w") as _f:
                    _js.dump(post_inlog, _f)
                print(f"saved {len(post_inlog)} post-cal INs -> {pp} (stopping)")
                # NOTE: no close_scan() here: the ritual is only valid
                # post-image; sent without a preceding image it wedges
                # the device deaf (proven). Post-cal leaves the session
                # open by design (diagnostic only).
                return 0
        else:
            print("skipping bulk OUT (--skip-bulk-out)")

    except (usb.core.USBTimeoutError, usb.core.USBError) as e:
        # Release the dead handle so the retry re-opens cleanly (else
        # set_configuration fails EBUSY on our own leaked claim). Success
        # paths still rely on process-exit implicit cleanup.
        try:
            usb.util.release_interface(dev, 0)
        except Exception:
            pass
        try:
            usb.util.dispose_resources(dev)
        except Exception:
            pass
        dev = None
        raise InitWedgeError(str(e))
    print("reading bulk IN image (motor should feed; "
          f"strip timeout {args.in_timeout}ms)...")
    raw = bulk_in_image_full(dev, args.mode, args.dpi, verbose=args.verbose,
                             timeout=args.in_timeout)
    # NOTE: interface released implicitly at process exit (proven era).
    # Explicit early release correlated with next-open vendor wedges.
    with open(args.raw, "wb") as f:
        f.write(raw)
    print(f"captured {len(raw)} bytes -> {args.raw}")
    if len(raw) > 0:
        close_scan(dev, args.mode, args.dpi, verbose=args.verbose)

    if len(raw) == 0:
        print("NO DOCUMENT: no image data (empty feeder?). "
              "Feed paper and retry. (SANE_STATUS_NO_DOCS equivalent.)")
        return 2

    width = cfg["width"]
    if not cfg["color"]:
        h, rem = render_gray(raw, width, args.out)
        print(f"rendered gray {width}x{h} (rem {rem}) -> {args.out}")
        if rem != 0:
            print("  WARNING: raw length not divisible by width; "
                  "trailing bytes dropped. Try brute-forcing width "
                  "2500-2560 if edges look slanted.")
        if key == ("gray", 150):
            print("  NOTE: 150-DPI width 1272 = 38160/30 (divisor-proven, "
                  "live-verified s150i).")
    else:
        if key == ("color", 150):
            print("  EXPERIMENTAL color150: assuming line-seq RGB triplets "
                  "like color300 (51 lines/strip = 17 groups) -- untested "
                  "live, validate visually.")
        h, rem = render_color(raw, width, args.out)
        print(f"rendered color lineseq-rgb {width}x{h} (rem {rem}) -> {args.out}")

    print("done. If image looks slanted/noisy, see LINUX_DRIVER_README.md "
          "'brute-force width' section.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
