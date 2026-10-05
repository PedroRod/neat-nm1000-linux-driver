# Neat NM-1000 Linux driver v1 (libusb prototype + SANE skeleton)

Device: `Neat Mobile Scanner` `USB 1f44:0001` `CN097P200185` `REV_0602`
(`Mobile Sheetfed Scanners`, CIS, USB-powered mini-USB, simplex).
Verified on Windows 10 Pro 64-bit (WIA `usbscan.sys` + TWAIN DS, no firmware blob).

## Files

- `nm1000_scan.py` — **the driver**. libusb replay + render. See `--help`.
- `nm1000-ctrl-{gray150,gray300,color300,gray600}.json` — ordered EP0 vendor
  init scripts (OUT setup+payload, IN setup+wLength), extracted from pcaps
  up to first bulk (standard descriptors + SET_CONFIGURATION excluded).
- `nm1000-{150gray,300gray,300color,600gray}-out.bin` — bulk OUT blobs (replayed verbatim).
- `nm1000-*-in-raw.bin` — captured bulk IN images (for render validation).
- `render-*.png` — render hypotheses (inspect these to validate widths/RGB).
- `60-neat-nm1000.rules` — udev rule (install + replug).
- `sane-neatnm1000.c` — SANE backend skeleton (options + NO_DOCS handling; port `nm1000_scan.py` to C for production).
- `replay_nm1000.py` — original bulk-only prototype (kept; `nm1000_scan.py --skip-ctrl` is its superset).
- `*.pcap`, `descriptors.txt`, `NeatMobileScanner.inf`, `device-info.txt` — ground truth captures.

## Quick start (connected scanner)

```bash
pip install --user pyusb pillow
sudo cp 60-neat-nm1000.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
# replug scanner, then:
ls -l /dev/bus/usb/*/*   # should show group scanner + rw
groups                   # you must be in scanner/plugdev (re-login if added)

# smoke test (no USB):
python3 nm1000_scan.py --dry-run --mode gray --dpi 300

# gray 300 DPI (default; feed paper, then run: bulk IN has 3 s idle timeout):
python3 nm1000_scan.py --mode gray --dpi 300 --raw scan.raw --out scan.png -v

# color 300 DPI / gray 150 / gray 600:
python3 nm1000_scan.py --mode color --dpi 300 --raw c.raw --out c.png -v
python3 nm1000_scan.py --mode gray --dpi 150 --raw s150.raw --out s150.png -v
python3 nm1000_scan.py --mode gray --dpi 600 --raw s600.raw --out s600.png -v
```

Exit codes: `0` scan + PNG ok, `2` **NO DOCUMENT** (zero image bytes — feed paper and retry; SANE `NO_DOCS` equivalent, not a hard failure), `1` error (permission/missing device — see message).

## Protocol (decoded from pcaps with pure-python USBPcap parser)

USBPcap: global `a1b2c3d4`, DLT 249; per-packet header `headerLen` 28 (control, incl. 1 B stage) vs 27 (bulk, no stage). `transfer` 0x02=control, 0x03=bulk, 0x01=interrupt. `endpoint` 0x00/0x80=EP0 OUT/IN, 0x02/0x81=bulk. `func` 0x000b=setup-class, 0x0017=vendor, 0x0008=complete, 0x0000=SET_CONFIGURATION, 0x0009=bulk. `devfield` == Wireshark `usb.device_address` (3=gray300, 4=color300, 5=150/600/empty).

- **Bulk EP2 is NOT the mode/DPI switch.** The 3×512 B command blocks are byte-identical across gray/color and 150/300 (third confirmation at 600). Tails `32 B` identical; middle tail `8c0a` repetition (8 B vs 16 B) is poll-timing noise. Only calibration scales: 10808 B ×3 (150/300) → 21608 B ×3 (600), same `0000..feff..` head. Calibration is host→scanner measured shading — replay verbatim.
- **Mode + DPI live in EP0 vendor OUT 64 B tables** (setup `40 04 83 00 00 00 40 00`). 15 tables/scan = 5× (01a0,2404,6600); first 3× identical (generic init), last 2× carry mode/DPI (programmed twice). IN setups (`c0 04 8e/84/0c/8c..`) are identical sets across scans (host polls same registers); device answers differ (status, not commands).
  - `01a0..` byte19: `00`=gray, `02`=color.
  - `6600..` byte47: `04`=gray, `00`=color.
  - `2404..` bytes33/35: DPI/mode gain (`150:85:43:96`, `300:82:a3:93`, `600:81:73:97+byte25`, `color:80:e3:90`). `01a0..` byte51 also moves (init `04` → final `0f` at 150/300/color, `02` at 600).
  - Small OUTs (`0200/0400/0800/3600/8c../8200`) identical across modes — only `4000/2400/3c00` vary. `3c00` (60 B) present in gray only (0× in color); `2400` (36 B) 2× gray300/color, 1× gray600.
- **Empty feeder** (`neat-empty-error.pcap`, 3 attempts): control-only + one bulk OUT `00000000` (4 B) + zero-length (frame 55/56) — unique to error path. Driver maps zero-image to `NO_DOCS`.
- **Polling** (skipped v1): vendor IN/OUT interleaved between bulk strips (1132 ctrl pkts gray300, 9678 gray600) + 2 B/8 B bulk polls and 2 B/256 B status reads on long scans (600: ~700×, idx 8584+). Scanner streams without it; add poll thread if 600 DPI stalls.
- **600 DPI warmup**: ~11k packets of 2 B/8 B polling before calibration (cal at pkt 11802 vs 402/422 for 150/300). Driver replays init then calibration directly, skipping warmup.

## Render (validate visually — operator call)

| capture | raw bytes | width (exact divisor) | height | PNG |
|---|---|---|---|---|
| gray300 | 3979976 | **2548** (not 2550), rem 0 | 1562 (~5.2") | `render-gray300-w2548.png` |
| gray150 | 947644 | **1348**, rem 0 (!=2548/2=1274) | 703 | `render-gray150-w1348.png` |
| gray600 | 15121500 | **5100**, rem 0 | 2965 (~4.9") | `render-gray600-w5100.png` |
| color300 | 34115176 | **2548 px RGB-interleaved** (7644 B/line, rem 4) | 4463 | `render-color300-interleaved-w2548.png` |

Gray renders as `L`; color default is pixel-interleaved RGB (alternative R/G/B line-sequential: 13389 = 4463×3 lines — driver also saves `-asgray.png` diagnostic). Color mid-mean 29 (range 21–55) vs gray 88 (8–171) — confirm which assembly reads as document. If edges slant, brute-force width 2500–2560 (gray300) / 7640–7660 B/line (color):
`python3 -c "from PIL import Image; d=open('scan.raw','rb').read(); [Image.frombytes('L',(w,len(d)//w),d[:len(d)//w*w]).save(f'w{w}.png') for w in range(2540,2560)]"`.

## SANE

See `sane-neatnm1000.c` header for build (`backend/neatnm1000.c` + `dll.conf`) and `scanimage -L` integration. Options: `resolution` (150/300/600 word-list), `mode` (Gray/Color string-list, color=300 only). `sane_start` ports `nm1000_scan.py`; zero image → `SANE_STATUS_NO_DOCS` (re-poll, not hard fail).

## Regeneration (no tshark needed — pure python)

Descriptors/OUT/IN/ctrl/bulk splits were extracted with the inline parsers in the analysis session (USBPcap `headerLen` 27/28, stage byte 27). To re-extract: parse pcap global `a1b2c3d4`, per-record `<IIII` + USBPcap header (`<H` headerLen, `<H` func@14, `B` info@16, `<H` bus@17/dev@19, `B` ep@21/trans@22, `<I` dataLen@23, `B` stage@27), data@28 (control) or @27 (bulk).

## Open questions for operator

1. Physical document lengths (validates 1562/703/2965/4463 line math; color doc ~2.9× gray?).
2. Which PNG reads correctly (gray `L` @2548/1348/5100; color interleaved vs sequential vs planar)?
3. Live `nm1000_scan.py -v` result on the connected unit (permission fixed?) — paste console + resulting PNG.
