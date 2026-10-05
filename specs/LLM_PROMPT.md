# LLM Prompt — Build a Linux driver for the Neat NM-1000 scanner

## Goal
Create a working Linux scanner driver (first a `libusb` userspace prototype that
reproduces the captured Windows scans, then a SANE backend) for the
**NeatReceipts NM-1000 portable sheetfed scanner**.

## Hardware / capture context (verified on Windows 10 Pro 64-bit)
- Device: `Neat Mobile Scanner`, `USB\VID_1F44&PID_0001\CN097P200185`, `REV_0602`
- Windows driver: `NeatMobileScanner.inf` v`3.0.3.0` (`11/20/2009`),
  `Class=Image` via `usbscan.sys` + `STI.USBSection`, WIA minidriver
  `{4C12EF64-5EB7-4df0-86CA-DF0596EE8526}` + TWAIN DS
  (`NeatMobileScanner32.ds` / `NeatMobileScanner64.ds`). No firmware (`.bin`/`.fw`)
  file ships with the driver.
- Product family: `Mobile Sheetfed Scanners` (portable, USB-powered, mini-USB,
  simplex, CIS). Trigger app: built-in **Windows Scan** (no Neat app installed).
- Two captures, same hardware, paper fed, `Source=Feeder`:
  - GRAY: `neat-windows-scan.pcap` — operator-confirmed grayscale
    (earlier mislabeled color), addr 3, 4464 pkts / 4.3 MB / 33.4 s.
  - COLOR: `neat-color-scan.pcap` — 300 DPI color, addr 4,
    11420 pkts / ~34 MB / 62.4 s (longer document than the gray one).
- Capture stack: Wireshark `4.6.8` + USBPcap `1.5.4.0` on `\\.\USBPcap1`
  (AMD `ROOT_HUB30`).

## USB descriptors (ground truth, see `descriptors.txt`, pcap frames 8/10)
- `idVendor 0x1f44`, `idProduct 0x0001`, `bcdDevice 0x0602`, 1 configuration
- `bConfigurationValue 1`, 1 interface
- `Interface 0.0: Class 0xFF / SubClass 0xFF / Protocol 0xFF`, 3 endpoints
- `EP 0x81 IN, Bulk (0x02), wMaxPacketSize 512` — image data
- `EP 0x02 OUT, Bulk (0x02), wMaxPacketSize 512` — commands / calibration
- `EP 0x83 IN, Interrupt (0x03), wMaxPacketSize 1` — button/status
  (zero packets in both scans; ignore for v1)
- `bmAttributes 0xA0`: bus-powered + remote-wakeup

## Captured protocol — GRAY (see `neat-windows-scan.pcap`, addr 3)
- ~4050 small control transfers (WIA/STI negotiation on EP0 — Linux only
  needs `set_configuration 1`).
- Bulk OUT `0x02`, 9 writes, 34002 bytes (`nm1000-300gray-out.bin`):
  `3× 10808 B` calibration (all 3 byte-identical, head
  `0000000000000000feffffff…`), `3× 512 B` commands (all 3 byte-identical,
  head `400005085a0ce90…`), tails `32 B (8c0a…)`, `8 B (8c0a…)`, `2 B (4605)`.
- Bulk IN `0x81`, 126 data transfers, 3979976 bytes
  (`nm1000-300gray-in-raw.bin`): `62×63488 + 62×212 + 30208 + 368`.
  Raw sensor values (`0x14–0xA0` ramp), no BMP/JPEG header.
- Size math at 300 DPI, 8.5″ width (2550 px): gray ⇒ ~1560 lines (~5.2″).

## Captured protocol — COLOR (see `neat-color-scan.pcap`, addr 4)
- Bulk OUT `0x02`: same 9-write shape, 34002 bytes (`nm1000-300color-out.bin`).
- Bulk IN `0x81`: 1117 data transfers, 34115176 bytes
  (`nm1000-300color-in-raw.bin`): `557×60928 + 557×224 + 53248 + 260 + 4`.
- KEY DIFF gray-vs-color: the three `512 B` command blocks and the
  `32/8/2 B` tails are **byte-identical** (0 diffs) — the mode selector is
  NOT in bulk OUT. The three `10808 B` calibration blocks differ almost
  entirely (~10.4–10.5K of 10808 bytes), but within each scan the 3 blocks
  are mutually identical, so they are per-scan measured shading data, not
  the mode switch. The gray/color switch therefore lives in the **control
  (EP0) transfers** — decode `usb.transfer_type==0x02` setup stages to find it.

## Captured protocol — EMPTY FEEDER error (see `neat-empty-error.pcap`, addr 5)
- 3 failed Scan attempts with no paper, one capture: 536 packets, ~27 KB,
  29.7 s. No image, no `10808`/`512` blocks, no interrupt `0x83` traffic.
- Entire USB exchange is control transfers plus exactly ONE bulk OUT on
  `0x02`: frame 55, 4 bytes `00000000`, followed by a zero-length packet
  (frame 56). That 4-byte zero write is the feeder/empty probe and is unique
  to the error path (success scans never send it; their smallest write is
  the 2-byte `4605` tail).
- Linux mapping: after init, if the device answers the empty probe with this
  control-only pattern and no image follows, report `SANE_STATUS_NO_DOCS`
  (do not treat as hard failure; let the frontend re-poll).

## Captured protocol — 150-DPI GRAY (see `neat-150gray.pcap`, addr 5)
- 2200 packets, ~1.1 MB, 19.3 s — same document as the 300-DPI gray scan at
  ~1/4 the bytes (947644 B IN: `24×37888 + 24×272 + 31744 + 56 + 4`), confirming
  pure resolution scaling with no geometry change.
- Bulk OUT `0x02`: same 9-write shape, 34010 bytes (`nm1000-150gray-out.bin`).
  All three `512 B` commands are **byte-identical to the 300-DPI gray**
  commands (0 diffs). Tails: `32 B` identical, middle tail is `8c0a` repeated
  8× (16 B) vs 4× (8 B) at 300 DPI — a bare repetition-count difference in a
  filler pattern, most likely status-poll timing noise, not a DPI code.
  Final `2 B (4605)` identical.
- CONCLUSION across all four scans: bulk OUT carries neither mode nor
  resolution. Both selectors live in the EP0 control transfers
   (`usb.transfer_type==0x02`); the bulk path (10808 cal + 512 cmd + tails,
   then raw IN) is mode/DPI-independent. Decode control setup stages next.

## Captured protocol — 600-DPI GRAY (see `neat-600gray.pcap`, addr 5)
- 25652 packets, ~16 MB, 49.4 s. IN image 15121500 B
  (`nm1000-600gray-in-raw.bin`): `247×60928 + 247×272 + 4608 + 492`.
  DPI ladder IN bytes — 150: 947644, 300: 3979976, 600: 15121500 —
  ratio `1 : 4.2 : 16.0`, textbook DPI-squared scaling of the same document.
- Bulk OUT: `3× 21608 B` calibration + `3× 512 B` commands + `32 B`
  (`nm1000-600gray-out.bin`, 66392 B). Calibration doubles vs 150/300
  (10808 → 21608, same `0000000000000000feffffff…` head): the cal table
  scales with sensor width. All three `512 B` commands again **byte-identical
  to 150/300 gray and to color** (0 diffs, third confirmation).
- New: progress polling on long scans — ~700× `2 B` OUT polls answered by
  `2 B` IN status words (`0100`, `0200`, `1400`…) plus `704× 256 B` status
  reads. Linux should answer/poll or ignore these; short scans complete
  without them, long scans interleave them with image strips.
- Calibration is host→scanner (OUT) and per-scan measured: replay captured
   tables verbatim for v1; expect mild shading error if lamp/paper differ.

## Captured protocol — 300-DPI GRAY repeat, longer doc (see `neat-300gray-r2.pcap`, addr 8)
- 5732 packets, ~8.9 MB, 53.2 s — same mode/DPI as the first gray scan but a
  much longer document (~2× bytes). Bulk OUT shape unchanged
  (`3× 10808 B` cal with the same head, `3× 512 B` commands with the same
  `40000508…` head, `32 B` + short tails).
- Proves scan length is NOT encoded in bulk OUT: 4.3 MB vs 8.9 MB docs,
  identical command structure. The scanner streams until the paper ends;
  Linux reads `0x81` until short transfer / timeout / status poll says done.

## Captured protocol — 300-DPI COLOR, same longer doc (see `neat-300color-long.pcap`, addr 8)
- 16102 packets, ~50 MB, 48.9 s — the SAME document as the gray repeat R2,
  scanned in color. Bulk OUT identical shape (`3× 10808 B` + `3× 512 B`);
  all three `512 B` commands **byte-identical to the same-doc gray** (0 diffs).
  Mode is definitively not in bulk OUT, even holding document constant.
- Bulk IN `0x81`: 1630 transfers, 49838880 B
  (`nm1000-300color-long-in-raw.bin`): `815× 60928 + 815× 224`.
  Same-doc gray gave 133 strips × 63488 (8.9 MB total): color moves ~6.1×
  more strips of similar strip bytes, total ratio 5.6×.
- HYPOTHESIS: color = 16-bit per channel RGB (6 B/px) vs gray 8-bit (1 B/px)
  = 6×. Verify by rendering: group the IN stream into 16-bit words (check
  high bytes small/near-zero) and assemble 3 planes; compare against an
  8-bit RGB-interleaved render of the same stream.

## Captured protocol — 150-DPI COLOR, longer doc (see `neat-150color.pcap`, addr 8)
- 4372 packets, ~12 MB, 37.0 s — the LONGER document (same as the R2 gray and
  300-color-long scans), scanned in color at 150 DPI.
- Bulk OUT `0x02`: `3× 10808 B` + `3× 512 B` + `32 + 16 + 2 B`
  (`nm1000-150color-out.bin`, 34010 B). All three `512 B` byte-identical to
  the 150-gray commands (0 diffs, fourth confirmation). Middle tail is 16 B
  of `8c0a` filler like 150 gray (vs 8 B at 300) — filler poll-count, not code.
- Bulk IN `0x81`: 372 transfers, 12066192 B
  (`nm1000-150color-in-raw.bin`): `186× 64512 + 186× 360`.
- Cross-checks (longer doc): 300-gray 8.9 MB → 150-color 12.1 MB ≈ 6/4×
  (mode 6× over DPI-quarter) ✓; 300-color 49.8 MB → 150-color 12.1 MB ≈ 1/4×
  (DPI²) ✓. Mode factor ~6× (16-bit/channel RGB hypothesis) holds at 150.

## Captured protocol — 150-DPI GRAY, longer doc (see `neat-150gray-long.pcap`, addr 8)
- 2962 packets, ~2.3 MB, 33.4 s — the LONGER document in grayscale at
  150 DPI. Completes the same-doc 2×2 matrix (150/300 × gray/color).
- Bulk IN `0x81`: 2107708 B (`nm1000-150gray-long-in-raw.bin`).
  Long-doc matrix: 150g 2.1M / 300g 8.9M / 150c 12.1M / 300c 49.8M —
  DPI² holds both modes (×4.2 gray, ×4.1 color), mode factor ~6× both DPIs.
- All three `512 B` byte-identical to the same-doc 150 color (fifth
  confirmation). OUT `34010 B` with the 16 B `8c0a` tail (150-pattern).

## EP0 control setup — CAPTURED IN FULL, partially decoded (see `control-*.txt`)
- USBPcap captures every control transfer; nothing was filtered. Each
  `control-<scan>.txt` lists all control packets as
  `frame / bRequest / wValue / wIndex / wLength / data_len`. Bulk-only replay
  is NOT sufficient — the lamp-on-no-feed symptom is exactly a missing/incorrect
  control handshake. Linux must reproduce the control sequence, not just bulk.
- Decoded so far (grouped setup signatures):
  - `bRequest=4, wValue=0x008e`, wIndex pages 290/16418/32546/48674 (64 B)
    + 64802 (4 B): paged data/status reads, count scales with scan size
    (126 @150 → 286 @300 → 834 @300-long → 993 @600). Generic, all scans.
  - `bRequest=4, wValue=0x0083` (len 2 and 64): ONLY in the empty capture
    (31× + 9×) — the paper-sensor/status register. Linux: poll it; empty
    pattern ⇒ `SANE_STATUS_NO_DOCS`. (Matches interrupt EP `0x83` numbering.)
  - `bRequest=4, wValue=0x0082`, wIndex 0/1 (8 B): heavy only in the 600-DPI
    scan (1660× + 1446×) — progress-poll reads for long transfers.
- Still open: the mode/DPI SELECTOR write (likely a rare OUT-direction setup
  among the thousands of IN reads — separate by bmRequestType and diff
  gray-vs-color / 150-vs-300 for OUT-direction setups unique to one side).
- Linux debug recipe for lamp-on-no-feed: capture the Linux attempt with
  `usbmon`, then diff its control setups frame-by-frame against
  `control-300gray-r1.txt`. First divergence = the bug (expected: a missing
  or wrong mode/DPI write before the bulk OUT sequence).

## File inventory (this folder)
- `neat-windows-scan.pcap` (4304978 B) — grayscale Windows Scan job, addr 3
- `neat-color-scan.pcap` (~34 MB) — color Windows Scan job, addr 4
- `neat-empty-error.pcap` (27997 B) — 3× empty-feeder failures, addr 5
- `descriptors-only.pcap` (13142 B) — injected-descriptor capture, frames 8/10
- `descriptors.txt` — decoded device/config/interface/endpoint descriptors
- `scan-summary.txt` — capinfos output for the grayscale scan pcap
- `bulk-in-distribution.txt` — data_len histogram for EP1 IN (grayscale)
- `NeatMobileScanner.inf` — Windows driver INF (VID/PID match, WIA/TWAIN model)
- `device-info.txt` — PnP friendly name / instance / class
- `nm1000-300gray-out.bin` (34002 B) + `.hex` — gray OUT writes in order
- `nm1000-300gray-in-raw.bin` (3979976 B) — gray concatenated IN bytes
- `neat-150gray.pcap` (1122508 B) — 150-DPI grayscale, same doc, addr 5
- `nm1000-150gray-out.bin` (34010 B) + `.hex` — 150-gray OUT writes in order
- `nm1000-150gray-in-raw.bin` (947644 B) — 150-gray concatenated IN bytes
- `neat-600gray.pcap` (~16 MB) — 600-DPI grayscale, same doc, addr 5
- `nm1000-600gray-out.bin` (66392 B) + `-bulk.hex` — 600-gray OUT (3×21608+3×512+32)
- `nm1000-600gray-in-raw.bin` (15121500 B) — 600-gray image IN bytes
- `neat-300gray-r2.pcap` (8872253 B) — 300-DPI gray repeat, longer doc, addr 8
- `nm1000-300gray-r2-out.hex` — R2 OUT writes (same 3×10808 + 3×512 shape)
- `neat-300color-long.pcap` (~50 MB) — 300-DPI color, SAME doc as R2, addr 8
- `nm1000-300color-long-out.hex` — same-doc color OUT (512s ≡ gray, 0 diffs)
- `nm1000-300color-long-in-raw.bin` (49838880 B) — same-doc color IN bytes
- `neat-150color.pcap` (~12 MB) — 150-DPI color, LONGER doc, addr 8
- `nm1000-150color-out.bin` (34010 B) + `.hex` — 150-color OUT (512s ≡ gray)
- `nm1000-150color-in-raw.bin` (12066192 B) — 150-color IN bytes
- `neat-150gray-long.pcap` (~2.3 MB) — 150-DPI gray, LONGER doc, addr 8
- `nm1000-150gray-long-out.bin` (34010 B) + `.hex` — same-doc 150-gray OUT
- `nm1000-150gray-long-in-raw.bin` (2107708 B) — same-doc 150-gray IN bytes
- `nm1000-300color-out.bin` (34002 B) + `.hex` — color OUT writes in order
- `nm1000-300color-in-raw.bin` (34115176 B) — color concatenated IN bytes
- `control-300gray-r1.txt` + `-r2`, `-300color-long`, `-150gray`, `-150gray-long`, `-150color`, `-600gray`, `-empty` — EP0 setup tables per scan
- `replay_nm1000.py` — Linux prototype (bulk path ONLY — must add control handshake, see EP0 section)

## What to build
1. **Reproduce verbatim**: `replay_nm1000.py` opens `1f44:0001`,
   `set_configuration(1)`, claims interface 0, writes the OUT blob in the
   9 captured lengths `(10808×3, 512×3, 32, 8, 2)` to `0x02`, then bulk-reads
   `0x81` (64 KiB chunks, 3 s timeout) until timeout. Save `scan.raw`.
   udev rule:
   `ATTRS{idVendor}=="1f44", ATTRS{idProduct}=="0001", MODE="0664", GROUP="scanner"`.
2. **Render**: try gray `(W=2550, H=len/2550)` and RGB-planar (split raw in 3,
   merge). Brute-force width around 2500–2560 if edges look slanted.
   Grayscale capture should render clean as gray; color capture decides the
   RGB assembly (sequential planes vs interleaved).
3. **Find mode + resolution**: diff the EP0 control transfers between the
   four pcaps (`usb.transfer_type==0x02`, setup bytes + 8/64-B payloads).
   Bulk is proven mode/DPI-independent (512 B identical across gray/color
   and 150/300; only filler poll-count `8c0a` varies).
4. **Productize** as a SANE backend (`sane-backends/doc/backend-writing.txt`,
   model on `sane-genesys`): options for resolution/mode, calibration replay,
   plane assembly, udev rule + `scanimage -L` integration.

## Regeneration commands (tshark)
- Descriptors: `-r descriptors-only.pcap -Y 'frame.number==8||frame.number==10' -V`
- Gray OUT hex: `-r neat-windows-scan.pcap -Y 'usb.device_address==3 && usb.endpoint_address.number==2 && usb.endpoint_address.direction==0 && usb.data_len>0' -T fields -e usb.capdata`
- Gray IN hex: same with `number==1 && direction==1`
- Color OUT/IN: `-r neat-color-scan.pcap` with `usb.device_address==4`, same endpoint filters.
- Concatenation order == frame-number order.

## Open questions for the operator
- Physical lengths of the scanned documents (validates line math)?
- Which render (gray vs RGB-planar) looks correct per capture?
- Capture matrix is complete for v1 (150/300 gray + 300 color + empty error).
