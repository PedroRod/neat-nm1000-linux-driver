# Neat NM-1000 Linux driver

Standalone Linux driver for the **Neat NM-1000** sheetfed scanner
(USB `1f44:0001`). Reverse-engineered from the Windows driver's USB
traffic — no vendor firmware blob, no Windows needed.

- SANE backend: works with `scanimage`, `simple-scan`, and any SANE frontend
- Reference driver: `nm1000_scan.py` CLI (pyusb)
- Gray 150/300/600 dpi + color 150/300 dpi, sheetfed-variable length
- Back-to-back scans without replugging (warm reuse supported)
- Every mode/DPI path verified live on hardware, cold and warm

## Requirements

- Linux with `libusb-1.0`, SANE (`libsane`), Python 3
- Debian/Ubuntu: `sudo apt install libusb-1.0-0-dev sane-utils python3-pil`

## Install (SANE backend)

```bash
gcc -fPIC -Wall -shared -o libsane-neatnm1000.so.1 sane-neatnm1000.c -lusb-1.0
sudo cp libsane-neatnm1000.so.1 /usr/lib/x86_64-linux-gnu/sane/
sudo mkdir -p /usr/share/sane/neatnm1000
sudo cp nm1000-ctrl-*.json nm1000-*-out.bin /usr/share/sane/neatnm1000/
echo neatnm1000 | sudo tee -a /etc/sane.d/dll.conf
sudo cp 60-neat-nm1000.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
```

Replug the scanner, stage paper fully until it stops, then scan:

```bash
scanimage -L   # expect: neatnm1000:libusb:BBB:AAA ... NM-1000
scanimage -d neatnm1000 --format pnm --resolution 300 --mode Gray > scan.pnm
python3 -c "from PIL import Image; Image.open('scan.pnm').save('scan.png')"
```

Options: `--resolution 150|300|600`, `--mode Gray|Color`
(no color600 — the hardware has no such path).

## Reference driver

```bash
pip install --user pyusb pillow
python3 nm1000_scan.py --mode gray --dpi 300 --raw s.raw --out s.png -v
python3 nm1000_scan.py --mode color --dpi 150 --raw c.raw --out c.png -v
```

Paper-free protocol check (exercises init + cal, no sheet needed):

```bash
python3 nm1000_scan.py --mode gray --dpi 300 --raw /tmp/p.raw \
  --stop-after-post-cal --no-paper-poll -v
```

## Scan modes

| Mode | Width | Notes |
|---|---|---|
| gray 150 | 1272 | needs 216 ms/strip pace (else stale lines) |
| gray 300 | 2548 | workhorse path |
| gray 600 | 5100 | 704-cycle sensor sweep first |
| color 150 | 1272 | line-sequential RGB triplets |
| color 300 | 2548 | line-sequential RGB triplets |

Widths are exact divisors of captured byte totals (`rem 0` on every
good scan). Raw CIS reads are dark (paper ~140 @300, ~55 @150);
renders apply Otsu auto-levels (background→235, ink→10).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `NO_DOCS` / exit 7 | empty feeder — stage paper fully until it stops, retry |
| `set_configuration failed` / dead device | replug scanner 30 s; never USB-reset it (drops off bus) |
| warm scan wedges | only physical replug recovers a deaf device; cold path re-arms automatically |
| `--format png` aborts | scanimage limitation — use `--format pnm` and convert (above) |

## Files

| File | Purpose |
|---|---|
| `sane-neatnm1000.c` | SANE backend (exports `sane_neatnm1000_*` only) |
| `nm1000_scan.py` | libusb reference driver CLI |
| `nm1000-ctrl-*.json` | ordered EP0 vendor init scripts per mode |
| `nm1000-*-out.bin` | bulk-OUT calibration blobs, replayed in captured splits |
| `60-neat-nm1000.rules` | udev permissions rule |
| `PROTOCOL.md` | full USB protocol spec (transfers, phases, sensor codes) |
| `specs/` | raw capture notes: decoded sequences, descriptors, session log |

## Upstream

A SANE merge request for the `neatnm1000` backend (pure `sanei_usb`
port of this code, with manpage, device spec, and release note) is in
progress against `sane-project/backends`.

License: GPL-2.0-or-later (see COPYING).
