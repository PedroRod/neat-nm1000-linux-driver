# Rollers don't move (lamp on) — debug notes 2026-10-03

(Couldn't append to root-owned `README.md` / `LLM_PROMPT.md`; merge this
there with `sudo chown pedro:pedro README.md LLM_PROMPT.md` first.)

## Live-validated control path (powered hub, no paper fed)

`python3 nm1000_scan.py --mode gray --dpi 300 --paper-timeout 6 -v`:
claim IF0 OK, init prefix 8 ops OK, feeder probe ACK `00` (matches Windows
r2 pkt69 and empty-error), sensor polls return `0555` (fresh-probe idle;
never in captures). Full sequence works electrically — rollers are a
protocol/state issue, not USB breakage.

## Root causes found in pcaps (all fixed in driver + backend)

1. **Cold feeder probe missing.** Fresh power-up needs
   `8200:088f001004000000` + bulk OUT `00000000` (4 B) + IN `0b000100`
   (ACK, always `00`) right after the 8c pair (r2 pkt64-69). Warm-session
   captures (r1 `neat-windows-scan.pcap`) lack it — an earlier scan had
   armed the feeder. Without it: lamp-on-no-feed. Both `nm1000_scan.py`
   (after op 8) and `sane-neatnm1000.c` (split replay part 1/2) now send it.
2. **8200 framing alignment (dup wedges fw).** Framing precedes every bulk
   in pcaps — but the first one (`004001…`, e.g. gray300 pkt420) is already
   the tail op of the init JSON replay, so frame only `i>=1`. Re-sending it
   hangs EP0 hard (4× timeouts, device drops off USB, power-cycle needed).
   Exception: gray600's JSON ends mid-warmup (tail `0000000302000000`), so
   only it needs `i==0` framing (`frame_first`/`is600`). Tails verified
   per-mode.
3. **Per-strip image 8200 is per-mode** (wrong value stalls):
   gray300 `00000010d4f80000`, gray150 `0000001010950000`,
   gray600 `0000001010ef0000`, color300 `00000010e0ee0000`,
   color150 `0000001068fd0000`. End-of-page variants differ too
   (`…70770000`, `…c8220000`, `…04d10000`, `…ec130000`, `…01040000`).
   Framing `00800010…` is DPI-specific (`…08000000` @300/600,
   `…10000000` @150). 600 tails differ: 32/8 B `b80b…` (not `8c0a`),
   final `dc05` (not `4605`); the 8+2 live outside the 66392 B blob and
   are now sent literally.
4. **Paper gate values** (setup `c0048e0022400200`, 2 B, 2nd byte always `55`):
   `3055` staged → go; `7055` empty; `3355` feeding; `7355→7055` paper-out
   → done; `0555` fresh-probe idle. Placement matters: the wait must wrap
   the first three `400200` reads *in situ* (after the 8c pair + probe +
   the early `0200`/`4102` polls) — polling `400200` right after the probe
   never flips. Both replayers now do this; standalone pre-polling was
   removed as a dead end.

## Operator checklist (top-down)

1. Power-cycle between EVERY attempt (unplug 5 s). Firmware latches.
2. Feed paper fully until it stops BEFORE the first `400200` wait (10 s
   per read × 3). `3055` = go; timeout = exit 2, feed and retry.
3. Lamp: bright white-green = rail good; faint red = sag. Rear USB3 port;
   USB2 powered hubs still limit 500 mA/port.
4. `--dry-run` prints the per-mode table in use (all five verified).
5. Still stuck: capture Linux attempt via usbmon, diff control setups vs
   `control-300gray-r1.txt` — first divergence = the bug. Also compare
   live `400200`/`4102` streams vs the values above.

## New mode: color150 (experimental)

`neat-150color.pcap` yielded `nm1000-ctrl-color150.json` + splits
(10808×3,512×3,32,16,2) + post2e `0258381c39…4a9501…` + post1000
`02506a043d003e003f01350036013765` + img8200 `0000001068fd0000` +
strips 64512+360. Render width open (try gray W=1348, RGB24 bpl=4044,
RGB48 bpl=8088 — nothing divides cleanly; judge visually).

## 2026-10-03 late: tail region was the motor/lamp gate (fixed, untested live)

Between last-512 and `2e00` the pcap has 13 OUTs + 3 INs the old replay
skipped: INs (`4102->d455`, `1c000100->00`, `480400` per-mode 4B), OUTs
`2800` (40B per-mode) / `0a00` (10B per-mode) / `1000` / `9d00`, framed
BULK32, framed BULK8/16, OUTs `0600` / `0400x3` (per-mode) / `0d01,0d00,
0d10,6b81,6320`, framed BULK2. Skipping it diverges post-cal reads
(`4102 f455` vs `8555`, `400300 39f455` vs `338555`) and the motor never
steps (zeros, status `3955`, no paper-out). Both replayers now send the
full ordered tail region (backend: `nm_tail_region()`; its 600-preamble
moved there from a misordered post-`2e00` slot). Per-mode values:
2800/0a00/0400x3 differ by DPI+mode (table in code); 1000/9d00/0600/
0d01/0d00/0d10/6b81/6320 constant. 600 tails: 32/8B `b80b..` (not `8c0a`),
final `dc05` (not `4605`).

## 150-DPI paper-out = 3955 (not 7355)

At 150 DPI the device reports `400200 -> 3955` once paper exits (bright
`0xff` content to ~strip 149, dark after); 300 reports `7355/7055`. All
exits (paper-out incl. 3955, cap, idle timeout) now drain end-of-scan
shorts so back-to-back scans don't wedge on stale fw context (that wedge
showed as a hang on the next run's final init op).

## True widths are strip-size divisors (smalls are image data, not headers)

Strips are uniform blobs split across usbfs reads (e.g. 63488+212 =
63700). True width must divide the strip: gray300 63700/2548=25,
gray150 38160/1272=30 (NOT 1348; s150c.raw 5914800B = 1272x4650 rem 0),
gray600 61200/5100=12, color300 61152/5096=12 (NOT 5100). Driver +
backend updated (gray150 W=1272, color300 W=5096).

## Root cause of static-line 150s: strip overrun (host faster than motor)

Windows strip cycles: gray300 90ms, gray150 216ms, gray600 38ms,
color300 38ms. My loop ran strips back-to-back (~15ms), so at 150 the fw
re-served its current line buffer (static stripes, A/B sensor-row offset
-> adjacent-line match 0.17, line+2 0.97). Fix: enforce per-mode minimum
strip cycle (MODE_CFG cycle). Also fixed widths to strip divisors:
gray150 1272 (=38160/30, was 1348), color300 5096 (=61152/12, was 5100).

## Boot handshake was the missing piece (feed never armed)

Windows waits after SET_CONFIG and polls 8B status on EP0x81 until
settled (cold r2: 16/06/20/27.. over ~19s, init at ~30s; warm: 04/2b..
~6.5s, init at ~10.6s) before vendor init. My driver slammed init at +0s:
accepted, but feed stayed disarmed -- every run so far was a static-line
capture (scan6/scan7 text = one receipt line repeated; 7355 = feed
timeout, not paper exit). Fix: boot_wait() (stale flush + poll until 8s
quiet, cap 40s) before init; EP0x83 confirmed untouched in all pcaps
(interrupt IN, never used). Re-test 150 gray cold with eyes on sheet.

## Manual 088f probe was poisoning 150 (REMOVED)

088f exists only in the cold 300gray-r2 capture; all warm captures
(150x2, windows-scan, 150color, 600gray) omit it. My driver injected it
manually for scripts lacking it inline (all 150 runs) WITHOUT r2's
a940/0600/0b01 follow-ups -> feeder left disarmed -> static lines, no
motion, eventual 3955. 300 always used the JSON-inline complete probe
-> fed. Fix: never manual-probe; replay inline-only. (600-gray also
found to alternate two per-strip 8200s: 0600000302000000/0e00000300010000
x~705 pairs + ef00 x247 -- driver 600 config needs rework before live.)

## CONFIRMED: cold-arm block was the feed gate (150 now feeds)

s150i with injected r2 ops 5-22: sheet fed, 30 strips, 7355 paper-out,
1272x930 rem 0, readable text (step1 0.93). Rule: cold fw accepts init
without the arm but never steps the motor. 300 always worked because its
cold-derived JSON carries the block inline; all warm-derived scripts
(150/600/color) need injection. Backend mirror landed on master (d06c267): op-array parser, cold-arm injection, boot parity, paced strips + paper-out.

## Milestone: 150 DPI feeds, image confirmed good (master d6c9319)

s150i: cold-arm injected -> sheet fed, 30 strips, 7355, 1272x930 rem 0,
user-confirmed readable. Backend mirror in progress: cycle field added
(0.216/0.090/0.038/0.039/0.216); still TODO: op-array parser with bulk
support, cold-arm injection, strip pacing + 7355/7055/3955 paper-out.

## Post-scan close needed for warm back-to-back (op207 wedge)

300-mode back-to-back scans wedge at the first cal-framer (s150i->s150h
gray150 worked, but scan6->scan7 and g300cmp->c300d wedged). Windows
sends a post-scan tail after final 7055 (0a20, 400200, 0312/0392/6f00/
6d1f/6b01, identical all modes); without it the fw context stays
half-open. Driver now sends it best-effort after drain. Also: inline
088f probe auto-skips on warm refusal (Windows warm inits omit it).

## True end = lid-dark, not 7155 (color full page recovered)

c300b overran (7155 isn't terminal; fw serves stale brights forever).
Cutting at 7155+2 truncated the ~35mm sensor-head remainder; the
remainder streams FRESH through the 7155 phase then goes lid-dark.
Fix: end on 3 consecutive lid-dark strips after any paper-out (64
post-out backstop; 3955-fault ends via lamp-off dark or the cap).
c300b-full.png (2548x1856) salvaged from the overrun run.

## Color150 live perfect (c150a 1272x986) -- all requested modes work

gray150/300 + color150/300 live-verified. Remaining: gray600 rework
(alternating per-strip 8200s), backend hardware run. Hanging = top
priority: explicit release + reset-and-retry landed (d891420); warm
reuse still unproven live (every recent run was cold post-replug).

## Gray600 structure decoded; poll sweep implemented (untested live)

600 = init + 704-cycle sensor sweep (header 0800/0a00/0c00/0400/0600 +
3x0e000302, then per cycle: 8B row-addr OUT (k*0x20 open-loop), 2B OUT
1008, 2B IN, 256B IN; 16ms/cycle) + 21608x3/512x3/32 cal + tails +
post_seq + ef00 image loop (247x 60928+272, same 7-vendor block).
_poll600() added before bulk cal. Backend still lacks the 600 poll.

## Hanging root-cause candidate: CLEAR_FEATURE (removed everywhere)

No capture contains CLEAR_FEATURE; my driver/backend sent clear_halt
after every claim. Cold tolerates it, but clearing a healthy bulk
endpoint desyncs data toggles -> next bulk-framing 8200 wedges on warm
reuse (op207 pattern). Removed from all open paths (kept only on real
bulk timeouts). Recovery reworked: NO usb reset (drops a confused
NM-1000 off-bus entirely, proven twice) -- fresh-open retry once, then
power-cycle message. 600 header fixed: JSON ends with framer
0000000302000000, poll completes it (BOUT 0400) first.

## Gray600 live perfect (s600a 5100x3756) -- ALL MODES WORK

Poll sweep + cal + tails + ef00 loop verified end to end (7355@248,
lid-dark tail, no cap needed... cap fired at 312 as backstop with dark
triple landing same strip). Remaining: backend hardware run, warm-reuse
validation (no-clear_halt + re-open retry unproven live).

## Warm wedge mechanism: fw output back-pressure (drain-until-clean)

Warm reuse wedges at the first bulk-framing 8200 (op207/209) while 200+
EP0 ops succeed: the fw refuses a new scan while unread bytes from the
last one sit queued (flow control), not a toggle/USB issue. Fixed-12
drains sufficed after small runs (150/gray300 warm reuse worked) but
not after big ones (600/color). Fix: drain until 3 consecutive timeouts
(cap 64) instead of fixed 12, driver + backend.

## Warm wedge persists (op207) despite drain-until-clean

s300x (cold, lid-dark end, clean drain) -> c300e warm wedged op207 again,
retry deaf (set_config fail). Drain-cleanliness is NOT the (only) cause.
New approach: reproduce paper-free (--stop-after-post-cal --no-paper-poll
needs no sheet) and bisect warm variables fast: same-mode reuse, skip-cal,
no-boot-wait, longer settle.

## Session check must predate claim (fw USB reboots on claim)

Node ctime jumped between runs without replug: claim/set_config
reboots the fw USB engine (same addr, new ctime) while app state
persists. Checking after claim always reads cold. Moved detection to
immediately after find.

## Adaptive init: skip warm-refused ops instead of session detection

Session-via-ctime failed (claim reboots fw USB: same addr, new ctime).
New design: always replay/inject the full arm block; per-op retry-once,
then skip iff op is warm-skippable (arm writes, telemetry INs, probe
zeros/ACK; never paper 400200 or table OUTs). Probe trio skips
atomically + follow-ups. Cold fw accepts everything (skips never fire
cold); warm fw refuses already-set ops -> degraded gracefully to the
warm shape. No session state, no flags.

## Explicit USB release implicated in vendor wedges (reverted)

Warm post-cal wedges on EVERY vendor op from op0 (vendor handler stuck,
not selective refusal), while cold works. Suspect: explicit
release_interface/dispose aborts fw post-run housekeeping (d891420
introduced it; no warm reuse has worked since). Reverted to
process-exit implicit cleanup (proven era). Adaptive skip retained
(it correctly skipped the whole warm prefix instead of wedging at op5).

## Verbatim end-of-scan ritual implemented (close_scan)

Every 150/300/color capture ends: 8200:0000000104000000 + BIN4, then
0250/20ff/0600:350036003700/01e0, status INs, re-prime tables, final
7055 + closing OUTs (tables IDENTICAL across modes; 600 uses only the
short 0a20/7055/5-OUT tail). Driver close_scan() runs after image and
post-cal (never on NO_DOCS/exceptions); backend mirrored. Hypothesis:
only this fully closes the fw scan context (drain alone insufficient).

## Primed-fw hypothesis: warm path may be image-only

Close ritual accepted post-image (BIN4 0000e315, all INs answered) yet
next full init still wedges at first cal-framer. New theory: after
close the fw is PRIMED (calibrated) and refuses re-init; warm path =
--skip-ctrl --skip-bulk-out straight to strip loop. Also fixed retry
handle leak (EBUSY on own claim). Testing image-only warm next.

## Settle-time hypothesis (untested): fw busy, not broken

All warm attempts fire within ~2 min of the previous run; the two that
worked had longer gaps. Maybe the fw needs minutes of post-scan
housekeeping and my immediate re-init collides (then my retries crash
it fully deaf). Test: cold post-cal, wait 5 min, warm post-cal. If it
passes, implement poll-until-ready or fixed settle.

## Settle-time FALSIFIED (2026-10-04): fw latched, not busy

Cold post-cal exit 0 (addr 069) -> 5 min untouched idle -> warm
post-cal wedged IDENTICALLY to immediate warm: prefix ops 0-15 all
warm-refused/skipped, op16 + op22 timeout, retry deaf
(set_config Other error). 5-min settle changes nothing. Fw holds scan
context open (post-cal leaves session open by design, no close) and
refuses re-init tables.

## Primed-fw FALSIFIED trio (2026-10-04, addr 070, gray300)

Full cold scan w1 perfect: 105 strips, paper-out 94 (7355), lid-dark
x3 at 105, drain +63700, close ritual all-OK incl final 7055,
2548x2650 rem 0, PNG mean 100.8 stdev 110 (real content). Then:
1. Image-only warm (--skip-ctrl --skip-bulk-out): vendors alive,
   400200 -> 3055 staged, but bulk IN 0 B (exit 2). Fw idle, no
   stream without cal kick. Motor needs re-cal.
2. Skip-init + cal warm (--skip-ctrl with bulk OUT): BULK OUT 0
   accepted, first vendor 8200 framing 4x timeout -> classic op207
   wedge -> retry EBUSY deaf. Bulk path refused too.
3. Full re-init warm (earlier): tables refused op16/22.
Reads OK, ALL vendor OUT writes refused post-close. Close ritual +
drain do not release fw scan context. Missing ground truth: no
multi-scan Windows capture exists (all pcaps single-scan). Unknown
whether Windows survives back-to-back without replug. Next: test
Windows back-to-back, or capture Windows 2nd-scan pcaps to diff.

## 3x pcap verdict (2026-10-04, NeatScanner2/neat-3x-backtoback.pcap)

Windows DID 3× gray300 same-doc, no replug, one SET_CONFIGURATION
(frame 5), no resets/stalls. Warm inits (scan2/scan3) are 193 ops,
IDENTICAL to each other, = cold init MINUS the 17-op arm block and the
4B zeros probe, everything else byte-identical (difflib: single block
move of 0b09/8c/8c before table-1, ZERO payload diffs in aligned
regions). Close ritual (01040000+BIN4 ... short tail) present all 3
scans. The NeatScanner2/LLM_PROMPT.md "bulk OUT only" warm theory is
disproven by the op dumps. Fix: live-probe the 6e00 opener (500 ms,
no retry); skip the block whole on refusal (+ gray300 pre-table
0b09/8c move). New flags: --no-boot-wait, --no-set-config (Windows
sends set_config once per plug; both suspect if the framer still
wedges — first warm attempt wedged at the final init-tail 8200 despite
byte-correct init).

## Prime suspect: re-set_configuration (2026-10-04)

Two warm attempts, byte-correct init, both wedge at the final
init-tail 8200 (op209) — with and without boot_wait. Notable: run 2's
probe was ACCEPTED (full cold sequence incl 088f sent, all accepted
until op209). Windows sends SET_CONFIGURATION once per plug; every
Linux run re-sends it, and claim/set_config observably reboots the fw
USB engine. Theory: re-set_config partially resets fw state (tables
accepted fresh-like, cal-framing gate confused). Next: warm with
--no-set-config, full log to file (done — see next entry).

## no-set-config breaks the framer wedge; 64K reads next (2026-10-04)

Warm --no-boot-wait --no-set-config: probe ACCEPTED, full init incl
088f + all 9 cal OUTs + post-bulk accepted (no-set-config was the
framer-wedge key). New failure: first image read (exact 63488 URB) →
LIBUSB_ERROR_OVERFLOW. Theory: skipped set_config leaves host/fw
bulk toggles disagreeing; exact-size URBs overflow while 64K URBs
self-sync on the strip short packet (backend 64K loop live-proven via
scan.pnm). Driver image loop switched to 64K reads (per-read vendors
+ pacing + paper/lid-dark, backend shape). Next: replug, cold default
(validates 64K cold), immediate warm --no-boot-wait --no-set-config.

## Warm back-to-back SCANS (2026-10-04, c4warm): framer fixed, 4B skew

--no-set-config warm completed exit 0 (6752200-class doc): init +
cal + image all accepted. Two artifacts: (1) leading 4B status word
(0000e90f) read as strip 1 (no-boot-wait leaves it queued; cold runs
never show it) → rem 4 line shift; (2) drain APPENDED 2 stale strips
(+127400). Fixes: drop leading ≤4B pre-image chunk (keep bigger as
image head); drain DISCARDS (never appends — post-end bytes are lid
repeats/7155 stale). Probe-accepted label no longer claims cold (fw
accepts arm writes warm too). Motor stall mid-page observed once —
likely staging, watching.

## SANE backend first hardware run OK (2026-10-04, addr 072)

ASan build (`-fsanitize=address,undefined`) `./neat-test-asan gray 300`:
6752200 B, rem 0, 2548x2650, raw mean 79 stdev 65 (real content,
same shape as driver w1). Earlier segfault was the stale pre-fix
binary (cycle/max_bytes field swap). scanimage integration pending
(install .so + dll.conf + data files, replug, scan with paper).

## scanimage -L segfault: generic sane_* exports (FIXED 2026-10-04)

`scanimage -L` + any `scanimage -d neatnm1000` segfaulted (stack
overflow, ASan: `sane_dll_get_devices` <-> `sane_neatnm1000_get_devices`
mutual recursion). Cause: the .so exported generic `sane_*` names
alongside `sane_neatnm1000_*`; they interpose the SANE dll
dispatcher's own symbols. Fix: `NM_LOCAL` (hidden visibility) on all
13 generic entry points; .so now exports only `sane_neatnm1000_*`
(verified `nm -D`, 13 versioned, 0 generic). `scanimage -L` lists
`neatnm1000:libusb:001:002` exit 0 via LD_LIBRARY_PATH test.
Reinstall fixed .so to pick it up.

## First scanimage capture OK (2026-10-04)

`scanimage -d neatnm1000 --format pnm --resolution 300 --mode Gray`:
PNM 6752237 B, header `P5 2548x2650`, raw 6752200 rem 0, mean 77.8
stdev 64.9. End-to-end SANE path live-proven (gray300).

## Intermittent warm motor stall (2026-10-05, single occurrence)

One warm SANE scan died at 24 lines (61152B real content, feed halted
~1/3, idle-timeout end). Retry on same plug perfect (105 strips, rem
0, close 7055). 1-in-6 warm runs; cold never. Proximate cause looks
like staging, not protocol (init+cal+post-bulk all accepted; motor
simply stopped mid-feed on powered hub). Watching; if it recurs
warm-only, suspect the skipped arm block carries a motor-drive kick
Windows replaces elsewhere.

## C has_arm len bug: arm NEVER skipped (FIXED 2026-10-05)

Backend warm stalls ×3 traced via dbg.log: full cold arm (6e00…
088f + zeros) sent warm, zero skips, NO `feeder state` print — yet
strings present in the installed .so. Cause: C parsed OUT `"6e00"` to
len 2 BYTES; the check wanted `len == 1`. has_arm never fired, so
every backend warm run resent the arm (Windows never does). Pattern
fits progressive poisoning: first warm arms tolerated (scans OK),
then fw latches into first-strip stall until replug. Driver unaffected
(python compares payload STRINGS). Fix: `len == 2`. Next: replug,
cold + 3× warm, expect `feeder state: warm, skipping` + rem 0 each.

## SANE warm reuse OK (2026-10-05)

Post-fix .so: `scanimage` on warm device prints `warm session,
skipping set_configuration...`, captures PNM 6688537 B (`P5
2548x2625`, raw rem 0). No replug, no wedge. SANE cold+warm parity
done for gray300.

## Warm CLOSED: true skip path verified live (2026-10-05, s6.pnm)

SANE warm with probe REFUSED → `feeder state: warm, skipping arm
block...` → pre-image 63700 kept → paper-out 95 → lid-dark 105 →
`P5 2548x2625` rem 0, exit 0. Earlier stall series root-caused as
paper jam (byte-identical 63188 across replug = mechanical, cleared
by path check) + small-pre-read overflow floods (fixed 64K touch).
Full matrix green: driver cold/warm, SANE cold/warm, skip/full-arm.
Remaining: warm spot-checks 150/600/color, simple-scan multi-page.

## All-mode cold+warm matrix green (2026-10-05)

Driver back-to-back per mode (replug between modes, no replug within):
gray150 1272x1350 rem 0, gray600 5100x5112 rem 0 + byte-identical
warm, color300 2548x2568 rem 0 + identical, color150 1272x1326 rem 0
+ identical. Pre-image handling held everywhere (flood-kept
63700/61152/64872, status dropped 0000e315/00000a13/00008618).
Cable fault mid-round (no enumeration, power LED on): data pins,
fixed by swap. SANE warm skip-arm verified (s6.pnm).
