# Neat NM-1000 USB protocol

Reverse-engineered from the Windows driver's USBPcap captures and
verified live on Linux. Everything below is pcap-verified and/or
live-verified; guesses are marked as such.

Device: USB `1f44:0001`, interface 0 class `FF/FF/FF` (vendor-specific).

## Endpoints and encodings

| EP | Dir | Type | Use |
|---|---|---|---|
| `0x81` | IN | bulk | image strips + status words |
| `0x02` | OUT | bulk | calibration blobs |
| `0x83` | IN | interrupt | **never used** (0 packets in every capture) |

USBPcap fields used while decoding: `headerLen` 28 = control,
27 = bulk; `func` 0017 = vendor request, 0009 = bulk, 000b/0008 =
std/complete; `trans` 02 = control, 03 = bulk.

Setup packets below are written as 8 raw bytes
`bm req val_lo val_hi idx_lo idx_hi len_lo len_hi`. Example:
`4004830000000200` = OUT vendor req `0x83`, wValue `0x0000`,
wIndex `0x0000`, 2 data bytes. `c0048e0022400200` = IN vendor req
`0x04`, wValue `0x8e00`, wIndex `0x2240`, 2 bytes back.

## Transfer classes

- **Vendor OUT** (`40...`): register writes, table downloads, framers.
  Small payloads (1–64 B), always accepted on a healthy device.
- **Vendor IN** (`c0...`): register/status reads (2–64 B).
- **Bulk OUT** (`0x02`): calibration image data in captured chunk
  sizes; every chunk is preceded by a vendor-`8200` framer
  (`4004820001000800` + 8 B payload, see per-mode tables).
- **Bulk IN** (`0x81`): image strips. The firmware short-packets each
  strip, so a 64 KiB read completes exactly on strip boundaries.

## Session shape (all modes)

1. **SET_CONFIGURATION once per plug.** The firmware's USB engine
   reboots if it is re-sent: warm scans must NOT re-send it.
2. **Boot handshake (cold only).** Drain bulk-IN until 8 s quiet
   (cap 40 s). Cold firmware emits status reports for ~19 s first;
   the feed only arms after it settles. Warm sessions skip this.
3. **Ordered EP0 init** from `nm1000-ctrl-*.json`, including the
   **cold-arm block** (cold only) and the **paper gate**.
4. **Framed bulk-OUT calibration** from `nm1000-*-out.bin` in captured
   splits, then the **tail region**, then **post-bulk vendors**.
5. **Strip loop**: per strip, one bulk-IN pair + 7 vendor INs +
   image-`8200` OUT, paced to the Windows median cycle.
6. **End**: paper-out remainder + lid-dark, drain-until-clean,
   **close ritual** (post-image only).

## Cold-arm block (the feed gate)

Warm-derived scripts skip r2 ops 5–22; a cold device then accepts init
but never steps the motor. The block (sent in order, 8 ms apart):

| # | Kind | Setup | Payload |
|---|---|---|---|
| 0–6 | OUT | `4004830000000200` | `6e00` `a700` `6f00` `0650` `6c00` `6e02` `6c00` |
| 7 | IN | `c0048e0022410200` | 2 B |
| 8 | OUT | `4004830000000200` | `0b01` |
| 9–10 | OUT | `400c8c0010000100` / `400c8c0013000100` | `0a` / `0e` |
| 11 | OUT | `4004820001000800` | `088f001004000000` |
| 12 | BULK OUT | — | `00000000` (4 zero bytes) |
| 13 | IN | `c00c8e000b000100` | 1 B (ACK) |
| 14 | OUT | `4004830000000200` | `a940` |
| 15 | OUT | `4004830000000600` | `51043a003b00` |
| 16 | OUT | `4004830000000200` | `0b01` |

`gray300`'s JSON carries this block inline (ops 5–22); the other modes'
scripts get it injected. Warm sessions skip it whole — except gray300,
which re-sends its ops 27–29 (`0b09`, `0a`, `0e`) up front, then
resumes at op 22 while skipping the duplicate 27–29.

## Paper gate and sensor codes

The first three `400200` reads (`c0048e0022400200`, 2 B) must return
`3055` (staged); anything else = empty feeder, abort with NO_DOCS.
Poll up to 10 s while prompting the user to stage paper.

| Value | Meaning |
|---|---|
| `3055` | staged, ready |
| `3155` / `3355` | feeding |
| `7355` | trailing edge at sensor (~17–35 mm of rows still under head) |
| `7155` / `7055` | scan closed / idle |
| `3955` | 150-DPI feed fault (terminal) |
| `0555` | fresh-probe idle |

`7155`-closed firmware serves stale brights forever, so **darkness,
not status, is the true end**: 3 consecutive lid-dark strips
(mean < 50) after any paper-out, backstopped by 64 post-out strips.

## Per-mode configuration

| Mode | JSON | BIN blob | Splits | Strip IN pair | Pace/strip |
|---|---|---|---|---|---|
| gray150 | `nm1000-ctrl-gray150.json` | `nm1000-150gray-out.bin` | 10808×3, 512×3, 32, 16, 2 | 37888 + 272 B, 30 lines | 216 ms |
| gray300 | `nm1000-ctrl-gray300.json` | `nm1000-300gray-out.bin` | 10808×3, 512×3, 32, 8, 2 | 63488 + 212 B, 25 lines | 90 ms |
| gray600 | `nm1000-ctrl-gray600.json` | `nm1000-600gray-out.bin` | 21608×3, 512×3, 32 | 60928 + 272 B, 12 lines | 39 ms |
| color300 | `nm1000-ctrl-color300.json` | `nm1000-300color-out.bin` | 10808×3, 512×3, 32, 8, 2 | 60928 + 224 B, 8 RGB groups | 38 ms |
| color150 | `nm1000-ctrl-color150.json` | `nm1000-150color-out.bin` | 10808×3, 512×3, 32, 16, 2 | 64512 + 360 B, 51 lines | 216 ms |

Image `8200` framers (`4004820000000800`): gray150 `0000001010950000`,
gray300 `00000010d4f80000`, gray600 `0000001010ef0000`,
color300 `00000010e0ee0000`, color150 `0000001068fd0000`.

Widths are exact divisors of captured totals (`rem 0` every good scan):
gray150 **1272** (= 38160/30), gray300 **2548** (= 63700/25), gray600
**5100** (= 61200/12), color modes are line-sequential RGB triplets
(group every 3 lines, NOT interleaved). Overrunning the 150 pace
re-serves stale lines — the 216 ms floor is mandatory there.

Bulk-OUT cal framing payloads (`4004820001000800`) precede every chunk;
the FIRST framing is the init JSON's tail op and must not be re-sent.
600's trailing 8 B (`b80bb80bb80bb80b`) + 2 B (`dc05`) tails are literal
(outside its blob).

## Strip loop detail

Per strip: image-`8200` OUT → bulk-IN pair → 7 vendor INs:

```
c0048e0022400200 (2 B, paper)   c0048e0022014000 (64 B)
c0048e0022404000 (64 B)         c0048e00227f4000 (64 B)
c0048e0022be4000 (64 B)         c0048e0022fd0400 (4 B)
c0048e0022410200 (2 B)
```

The 64 B regs carry an A/B phase toggle bit; 150-DPI lines arrive in
staggered pairs (dedup/average to reconstruct). After the last strip,
drain bulk-IN with plain reads until 3 consecutive misses (cap 64):
leftovers back-pressure the firmware into refusing the next session.

## 600-DPI sensor sweep

Before bulk cal, a 704-cycle open-loop sweep: header framers once,
then per cycle [8 B row-address OUT | 2 B OUT | 2 B IN | 256 B IN].
Bulk-OUT framer `4004820001000800`, bulk-IN framer
`4004820000000800`; addresses `k*0x20`; IN data discarded.

## Close ritual (post-image only, best-effort)

`8200:0000000104000000` + 4 B read, `0250/20ff/0600:350036003700/
01e0`, status INs incl. `4b0400`, re-prime tables (mode-generic
constants), final `7055` + closing OUTs (`0a20/0312/0392/6f00/6d1f/
6b01`). 600 uses the short tail only. Without it the firmware holds
the scan context and the next init wedges.

## Never do this

- **CLEAR_FEATURE**: absent from every capture; clearing a healthy
  endpoint desyncs toggles and wedges warm reuse.
- **USB reset on a confused device**: drops it off the bus (proven
  twice). Only physical replug recovers a deaf NM-1000.

## Code map

- `nm1000_scan.py`: reference driver, same phase order as above.
- `sane-neatnm1000.c`: `sane_start` = init+gate, `nm_scan_full` =
  cal+tail+strips+drain, `nm_close_scan` = ritual, `nm_poll600` =
  sweep, stamp file = warm detection.

## Source records

`specs/` holds the underlying material: per-capture decoded control
sequences (`control-*.txt`), endpoint/descriptor dumps
(`descriptors.txt`, `device-info.txt`, `bulk-in-distribution.txt`),
and the chronological session log (`ROLLERS_DEBUG.md`) with every
finding in the order it was proven. The raw `.pcap` captures (266 MB)
are local-only; the shipped JSON/BIN files encode every byte sent.
