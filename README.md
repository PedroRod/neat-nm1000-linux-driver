# Neat NM-1000 Linux driver

Standalone SANE backend + reference driver for the Neat NM-1000
sheetfed scanner (USB `1f44:0001`). Reverse-engineered from the Windows
driver's USB traffic; no vendor firmware blob needed.

Gray 150/300/600 dpi and color 150/300 dpi, sheetfed-variable length.
All six paths verified live, cold and warm (replug-free back-to-back
scans supported).

## SANE backend (recommended)

```bash
sudo apt install libusb-1.0-0-dev libsane python3-pil
gcc -fPIC -Wall -shared -o libsane-neatnm1000.so.1 sane-neatnm1000.c -lusb-1.0
sudo cp libsane-neatnm1000.so.1 /usr/lib/x86_64-linux-gnu/sane/
sudo mkdir -p /usr/share/sane/neatnm1000
sudo cp nm1000-ctrl-*.json nm1000-*-out.bin /usr/share/sane/neatnm1000/
echo neatnm1000 | sudo tee -a /etc/sane.d/dll.conf
sudo cp 60-neat-nm1000.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
# replug scanner, stage paper, then:
scanimage -d neatnm1000 --format pnm --resolution 300 --mode Gray > scan.pnm
python3 -c "from PIL import Image; Image.open('scan.pnm').save('scan.png')"
```

`--format png` aborts inside scanimage (upstream buffered-PNG path);
convert from PNM as above. Empty feeder returns NO_DOCS (exit 7).

## Reference driver

```bash
pip install --user pyusb pillow
python3 nm1000_scan.py --mode gray --dpi 300 --raw s.raw --out s.png -v
```

## Files

| File | Purpose |
|---|---|
| `sane-neatnm1000.c` | SANE backend (hidden generic symbols, exports `sane_neatnm1000_*` only) |
| `nm1000_scan.py` | libusb reference driver, live-proven CLI |
| `nm1000-ctrl-*.json` | Ordered EP0 vendor init scripts per mode |
| `nm1000-*-out.bin` | Bulk-OUT calibration blobs, replayed in captured splits |
| `60-neat-nm1000.rules` | udev permissions rule |
| `PROTOCOL.md` | Full USB protocol spec (transfers, phases, sensor codes) |
| `specs/` | Raw capture notes: decoded control sequences, descriptors, full session log (`ROLLERS_DEBUG.md`). The 266 MB `.pcap` captures stay local (over GitHub's file cap); the JSON/BIN above encode every byte sent. |

## Notes

- Never CLEAR_FEATURE / USB-reset this device (wedges/drops it); only
  physical replug recovers a deaf device.
- Warm reuse: repeated scans on the same plugged device skip the boot
  handshake + feed arming, matching the vendor driver.
- An upstream SANE merge request (`neatnm1000` backend over `sanei_usb`,
  with manpage + device spec + release note) is in progress from this
  code.

License: GPL-2.0-or-later (see COPYING).
