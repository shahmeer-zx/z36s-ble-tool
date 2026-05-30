"""
Z36s BLE Recon & Control Tool  ·  v2.1 (Device Selector Update)
Targets: DA14583-class watch (LB726(D), firmware V04409)

Improvements over v2.0:
  - Interactive BLE device selection menu on startup if no specific address is given
  - Displays RSSI and device name/address for better targeting
  - Maintains existing fallback connection loops and robust REPL
"""

from __future__ import annotations

import asyncio
import json
import struct
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Optional

try:
    from bleak import BleakClient, BleakError, BleakScanner
    from bleak.backends.characteristic import BleakGATTCharacteristic
except ImportError:
    print("bleak not found.  Run:  pip install bleak")
    sys.exit(1)

# ── ANSI colours ─────────────────────────────────────────────────────────────
C = {
    "R":  "\033[92m",   # green  – received
    "S":  "\033[94m",   # blue   – sent
    "E":  "\033[91m",   # red    – error
    "I":  "\033[93m",   # yellow – info / decoded
    "D":  "\033[96m",   # cyan   – debug
    "W":  "\033[95m",   # magenta – warning
    "X":  "\033[0m",    # reset
    "B":  "\033[1m",    # bold
    "DIM":"\033[2m",
}

BANNER = f"""{C['B']}{C['I']}
 ████████╗██████╗  ██████╗███████╗
    ╚══██╔╝╚════██╗██╔════╝██╔════╝
      ██╔╝  █████╔╝███████╗███████╗
     ██╔╝   ╚═══██╗██╔═══╝╚════██║
    ██████╗██████╔╝╚██████╗███████║
    ╚═════╝╚═════╝  ╚═════╝╚══════╝
{C['X']}{C['D']}  Z36s / DA14583 BLE Control Shell  v2.1{C['X']}
"""

HELP = f"""
{C['B']}Commands:{C['X']}
  {C['I']}info{C['X']}               Dump GATT device info + battery
  {C['I']}ping{C['X']}               Send 0x00 keep-alive
  {C['I']}time{C['X']}               Sync phone time → watch
  {C['I']}steps{C['X']}              Request today's step count
  {C['I']}hr{C['X']}                 Request heart-rate reading
  {C['I']}bp{C['X']}                 Request blood-pressure reading
  {C['I']}spo2{C['X']}               Request SpO2 reading
  {C['I']}vib [N]{C['X']}            Vibrate N times (default 1)
  {C['I']}vib off{C['X']}            Stop vibration
  {C['I']}find{C['X']}               Find-my-phone ping
  {C['I']}ota{C['X']}                Dump OTA / CTRL channel state
  {C['I']}raw XX XX ...{C['X']}      Send raw hex bytes to WRITE char
  {C['I']}ctrl XX ...{C['X']}        Write hex bytes to CTRL char
  {C['I']}read CHAR{C['X']}          Read UUID or alias (ctrl / batt)
  {C['I']}probe [XX YY]{C['X']}      Brute-force single-byte commands
  {C['I']}probe2 XX{C['X']}          Brute-force [XX 00..FF]
  {C['I']}probe3 XX YY{C['X']}       Brute-force [XX YY 00..FF]
  {C['I']}test{C['X']}               Send known-good packet sequence
  {C['I']}watch{C['X']}              Toggle live notification dump
  {C['I']}save [FILE]{C['X']}        Save session log (JSON + txt)
  {C['I']}quit{C['X']}               Disconnect and exit
"""

# ── UUIDs ─────────────────────────────────────────────────────────────────────
WRITE_CHAR   = "6e400002-b5a3-f393-e0a9-e50e24dcca9d"  # W / WNR → commands to watch
NOTIFY_CHAR  = "6e400003-b5a3-f393-e0a9-e50e24dcca9d"  # N       ← responses from watch
CTRL_CHAR    = "6e400004-b5a3-f393-e0a9-e50e24dcca9d"  # N R WNR ← OTA / state control
BATTERY_CHAR = "00002a19-0000-1000-8000-00805f9b34fb"

DIS_CHARS = {
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software",
}

CHAR_ALIASES = {
    "ctrl": CTRL_CHAR,
    "batt": BATTERY_CHAR,
    "battery": BATTERY_CHAR,
    "write": WRITE_CHAR,
    "notify": NOTIFY_CHAR,
}

# ── Command payloads ──────────────────────────────────────────────────────────
CMDS: Dict[str, bytes] = {
    "ping":        bytes([0x00]),
    "status":      bytes([0x01]),
    "get_steps":   bytes([0xB1]),
    "get_hr":      bytes([0xD0]),
    "get_bp":      bytes([0xD2]),
    "get_spo2":    bytes([0xD4]),
    "vibrate":     bytes([0xCD, 0x00, 0x05, 0x1C, 0x01, 0x04, 0x00, 0x00]),  # 1 pulse
    "vibrate2":    bytes([0xCD, 0x00, 0x05, 0x1C, 0x02, 0x04, 0x00, 0x00]),  # 2 pulses
    "vibrate3":    bytes([0xCD, 0x00, 0x05, 0x1C, 0x03, 0x04, 0x00, 0x00]),  # 3 pulses
    "vibrate_off": bytes([0xCD, 0x00, 0x05, 0x1C, 0x00, 0x04, 0x00, 0x00]),  # 0 = stop
    "find_phone":  bytes([0x71, 0x01]),
    "ota_mode":    bytes([0xFE, 0x01]),
}

# ── Session state ─────────────────────────────────────────────────────────────
class Session:
    def __init__(self) -> None:
        self.log_entries: list[dict] = []
        self.live_watch = True
        self._probe_responses: Dict[int, bytes] = {}
        self._probe_event = asyncio.Event()
        self._probing = False
        self._current_probe_key = 0

    def ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def log(self, tag: str, msg: str, color: str = "") -> None:
        entry = {"t": self.ts(), "tag": tag, "msg": msg}
        self.log_entries.append(entry)
        if self.live_watch or tag in ("ERROR", "DECODE", "INFO"):
            prefix = f"{C.get(color, '')}"
            print(f"{prefix}[{entry['t']}] [{tag:<6}] {msg}{C['X']}")

    def on_notify(self, sender: BleakGATTCharacteristic, data: bytearray) -> None:
        hex_str  = data.hex(" ")
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        self.log("NOTIFY", f"{hex_str}  │  {ascii_str}", "R")
        self._maybe_capture_probe(data)
        self._decode(data)

    def on_ctrl(self, sender: BleakGATTCharacteristic, data: bytearray) -> None:
        self.log("CTRL", f"{data.hex(' ')}  (len={len(data)})", "R")

    def _maybe_capture_probe(self, data: bytearray) -> None:
        if self._probing:
            self._probe_responses[self._current_probe_key] = bytes(data)
            self._probe_event.set()

    def _decode(self, data: bytearray) -> None:
        if not data:
            return
        cmd = data[0]

        if cmd == 0xA1 and len(data) >= 7:
            _, y, mo, d, h, mi, s = data[:7]
            self.log("DECODE", f"Time → 20{y:02d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}", "I")

        elif cmd == 0xB1 and len(data) >= 5:
            steps = struct.unpack_from(">I", data, 1)[0]
            self.log("DECODE", f"Steps → {steps:,}", "I")

        elif cmd == 0xB2 and len(data) >= 9:
            steps    = struct.unpack_from(">I", data, 1)[0]
            calories = struct.unpack_from(">H", data, 5)[0]
            dist_m   = struct.unpack_from(">H", data, 7)[0]
            self.log("DECODE", f"Steps={steps:,}  Cal={calories}  Dist={dist_m}m", "I")

        elif cmd == 0xCD and len(data) >= 5:
            count    = data[4] if len(data) > 4 else data[1]
            duration = data[3] if len(data) > 3 else 0
            if count == 0:
                self.log("DECODE", "Vibrate → STOP", "I")
            else:
                self.log("DECODE", f"Vibrate → {count}× pulse  (duration byte=0x{duration:02X}={duration})", "I")

        elif cmd == 0xD0 and len(data) >= 2:
            self.log("DECODE", f"Heart rate → {data[1]} bpm", "I")

        elif cmd == 0xD2 and len(data) >= 3:
            self.log("DECODE", f"Blood pressure → {data[1]}/{data[2]} mmHg", "I")

        elif cmd == 0xD4 and len(data) >= 2:
            self.log("DECODE", f"SpO2 → {data[1]}%", "I")

        elif cmd == 0xD1 and len(data) >= 2:
            self.log("DECODE", f"Battery (response) → {data[1]}%", "I")

        elif cmd == 0x71 and len(data) >= 2:
            state = "ON" if data[1] else "OFF"
            self.log("DECODE", f"Find-phone ack → {state}", "I")

    def save(self, path: Optional[str] = None) -> Path:
        stem = path or f"z36s_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        json_path = Path(stem + ".json")
        json_path.write_text(json.dumps(self.log_entries, indent=2))
        txt_path = Path(stem + ".txt")
        txt_path.write_text(
            "\n".join(f"[{e['t']}] [{e['tag']:<6}] {e['msg']}" for e in self.log_entries)
        )
        return txt_path


# ── BLE helpers ───────────────────────────────────────────────────────────────
async def send(client: BleakClient, data: bytes,
               char: str = WRITE_CHAR, sess: Optional[Session] = None) -> None:
    await client.write_gatt_char(char, bytearray(data), response=False)
    if sess:
        sess.log("SENT", data.hex(" "), "S")
    else:
        print(f"{C['S']}[SENT  ] {data.hex(' ')}{C['X']}")


async def read_char(client: BleakClient, uuid: str) -> Optional[bytes]:
    try:
        return bytes(await client.read_gatt_char(uuid))
    except Exception:
        return None


async def dump_device_info(client: BleakClient, sess: Session) -> None:
    print(f"\n{C['B']}─── Device Information {'─'*35}{C['X']}")
    for uuid, name in DIS_CHARS.items():
        val = await read_char(client, uuid)
        if val:
            text = val.decode("utf-8", errors="replace").rstrip("\x00")
            print(f"  {name:<14}: {C['I']}{text}{C['X']}  {C['DIM']}({val.hex(' ')}){C['X']}")
        else:
            print(f"  {name:<14}: {C['DIM']}(not available){C['X']}")

    batt = await read_char(client, BATTERY_CHAR)
    if batt:
        level = batt[0]
        bar   = "█" * (level // 10) + "░" * (10 - level // 10)
        print(f"  {'Battery':<14}: {C['I']}{level}%{C['X']}  [{bar}]")

    ctrl = await read_char(client, CTRL_CHAR)
    if ctrl:
        print(f"  {'CTRL (0004)':<14}: {C['D']}{ctrl.hex(' ')}{C['X']}")

    print(f"{C['B']}{'─'*55}{C['X']}\n")


# ── Interactive Discovery Menu ────────────────────────────────────────────────
async def select_ble_device() -> str:
    """Scan for all nearby BLE devices and let the user select one via a menu."""
    print(f"\n{C['I']}Scanning for BLE devices (5 seconds)...{C['X']}")
    devices = await BleakScanner.discover(timeout=5.0)
    
    if not devices:
        print(f"{C['E']}No BLE devices discovered nearby.{C['X']}")
        sys.exit(1)
        
    print(f"\n{C['B']}── Discovered Devices {'─'*36}{C['X']}")
    
    # Safe extraction of RSSI to prevent AttributeError on macOS/CoreBluetooth
    def get_dev_rssi(d):
        rssi = getattr(d, 'rssi', None)
        if rssi is None and hasattr(d, 'details') and d.details:
            # Some bleak backends nest it inside backend-specific details
            if isinstance(d.details, dict):
                rssi = d.details.get('RSSI')
        return rssi or -100

    # Sort devices safely
    sorted_devices = sorted(devices, key=get_dev_rssi, reverse=True)
    
    for idx, dev in enumerate(sorted_devices, start=1):
        name = dev.name if dev.name else "Unknown Device"
        name_color = C['I'] if "Z36" in name else C['X']
        rssi_val = get_dev_rssi(dev)
        rssi_str = f"{rssi_val}dBm" if rssi_val != -100 else "N/A"
        
        print(f"  [{C['B']}{idx}{C['X']}] {name_color}{name:<25}{C['X']} Address: {C['D']}{dev.address}{C['X']}  (RSSI: {rssi_str})")
    print(f"{C['B']}{'─'*55}{C['X']}\n")
    
    while True:
        try:
            choice = input(f"{C['B']}Select device number [1-{len(sorted_devices)}]:{C['X']} ").strip()
            if not choice:
                continue
            idx_choice = int(choice)
            if 1 <= idx_choice <= len(sorted_devices):
                selected = sorted_devices[idx_choice - 1]
                print(f"{C['R']}Target acquired: {selected.name or 'Unknown'} [{selected.address}]{C['X']}")
                return selected.address
            else:
                print(f"{C['W']}Invalid index selection.{C['X']}")
        except ValueError:
            print(f"{C['E']}Please enter a valid digit number.{C['X']}")
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C['W']}Selection canceled.{C['X']}")
            sys.exit(0)


# ── Time sync ─────────────────────────────────────────────────────────────────
async def set_time(client: BleakClient, sess: Session) -> None:
    now = datetime.now()
    wday = (now.weekday() + 1) % 7
    payload = bytes([
        0xA1,
        now.year % 100,
        now.month,
        now.day,
        wday,
        now.hour,
        now.minute,
        now.second,
    ])
    await send(client, payload, sess=sess)
    sess.log("INFO", f"Time sync → {now.strftime('%Y-%m-%d %H:%M:%S')} (weekday={wday})", "I")


# ── Brute-probe ───────────────────────────────────────────────────────────────
async def _probe_range(
    client: BleakClient,
    sess: Session,
    packets: list[bytes],
    label: str,
    delay: float = 0.25,
    response_timeout: float = 0.2,
) -> Dict[int, bytes]:
    results: Dict[int, bytes] = {}

    try:
        await client.stop_notify(NOTIFY_CHAR)
    except Exception:
        pass
    sess._probe_responses.clear()
    sess._probing = True

    async def _capture(sender: BleakGATTCharacteristic, data: bytearray) -> None:
        if sess._probing:
            results[sess._current_probe_key] = bytes(data)
            sess._probe_event.set()
        hex_str = data.hex(" ")
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        sess.log("NOTIFY", f"{hex_str}  │  {ascii_str}", "R")

    await client.start_notify(NOTIFY_CHAR, _capture)

    total = len(packets)
    for i, pkt in enumerate(packets):
        sess._current_probe_key = i
        sess._probe_event.clear()
        pct = (i + 1) / total * 100
        print(f"\r{C['D']}[{label}] {pkt.hex(' ')}  ({pct:5.1f}%)  hits: {len(results)}{C['X']}",
              end="", flush=True)
        try:
            await client.write_gatt_char(WRITE_CHAR, bytearray(pkt), response=False)
            try:
                await asyncio.wait_for(sess._probe_event.wait(), timeout=response_timeout)
            except asyncio.TimeoutError:
                pass
            await asyncio.sleep(delay - response_timeout if delay > response_timeout else 0)
        except BleakError as e:
            sess.log("ERROR", f"{pkt.hex(' ')}: {e}", "E")

    sess._probing = False
    print()

    try:
        await client.stop_notify(NOTIFY_CHAR)
    except Exception:
        pass
    await client.start_notify(NOTIFY_CHAR, sess.on_notify)

    return results


def _print_probe_results(results: Dict[int, bytes], packets: list[bytes]) -> None:
    print(f"\n{C['B']}── Probe Results {'─'*40}{C['X']}")
    if not results:
        print(f"  {C['DIM']}No responses received.{C['X']}")
    else:
        for i, data in sorted(results.items()):
            pkt = packets[i]
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            print(f"  {C['S']}{pkt.hex(' ')}{C['X']}  →  {C['R']}{data.hex(' ')}{C['X']}  │  {ascii_str}")
    print(f"{C['B']}{'─'*57}{C['X']}\n")


async def brute_probe(client: BleakClient, sess: Session,
                      start: int = 0x00, end: int = 0xFF) -> None:
    packets = [bytes([b]) for b in range(start, end + 1)]
    print(f"\n{C['I']}[PROBE] {start:#04x} → {end:#04x}  ({len(packets)} packets){C['X']}")
    results = await _probe_range(client, sess, packets, "PROBE")
    _print_probe_results(results, packets)


async def probe2(client: BleakClient, sess: Session, first: int) -> None:
    packets = [bytes([first, b]) for b in range(0x100)]
    print(f"\n{C['I']}[PROBE2] {first:#04x} 00 → {first:#04x} ff{C['X']}")
    results = await _probe_range(client, sess, packets, "PROBE2")
    _print_probe_results(results, packets)


async def probe3(client: BleakClient, sess: Session, first: int, second: int) -> None:
    packets = [bytes([first, second, b]) for b in range(0x100)]
    print(f"\n{C['I']}[PROBE3] {first:#04x} {second:#04x} 00 → ff{C['X']}")
    results = await _probe_range(client, sess, packets, "PROBE3")
    _print_probe_results(results, packets)


async def test_known_commands(client: BleakClient, sess: Session) -> None:
    tests = [
        bytes([0x01]),
        bytes([0x01, 0x00]),
        bytes([0xCD]),
        bytes([0xCD, 0x00]),
        bytes([0xCD, 0x00, 0x05]),
        bytes([0xCD, 0x00, 0x05, 0x1C]),
        bytes([0xAB, 0x00, 0x04, 0xFF, 0x91, 0x80, 0x00]),
        bytes([0xD0]),
        bytes([0xB1]),
        bytes([0xD2]),
        bytes([0xD4]),
        bytes([0xA1]),
    ]
    print(f"\n{C['B']}=== Testing {len(tests)} Known Packets ==={C['X']}\n")
    for pkt in tests:
        await send(client, pkt, sess=sess)
        await asyncio.sleep(1.5)


# ── Async input helper (non-blocking on all platforms) ────────────────────────
async def async_input(prompt: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: input(prompt))


# ── REPL ──────────────────────────────────────────────────────────────────────
async def repl(client: BleakClient, sess: Session) -> None:
    print(HELP)

    while True:
        try:
            line = (await async_input(f"{C['B']}z36s>{C['X']} ")).strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not line:
            continue

        parts = line.split()
        cmd   = parts[0].lower()

        try:
            if cmd == "quit":
                break

            elif cmd == "info":
                await dump_device_info(client, sess)

            elif cmd == "save":
                path = parts[1] if len(parts) > 1 else None
                saved = sess.save(path)
                print(f"{C['I']}Session saved → {saved}  (+.json){C['X']}")

            elif cmd == "watch":
                sess.live_watch = not sess.live_watch
                state = "ON" if sess.live_watch else "OFF"
                print(f"{C['I']}Live notification dump: {state}{C['X']}")

            elif cmd == "test":
                await test_known_commands(client, sess)

            elif cmd == "ping":
                await send(client, CMDS["ping"], sess=sess)

            elif cmd == "time":
                await set_time(client, sess)

            elif cmd == "steps":
                await send(client, CMDS["get_steps"], sess=sess)

            elif cmd == "hr":
                await send(client, CMDS["get_hr"], sess=sess)

            elif cmd == "bp":
                await send(client, CMDS["get_bp"], sess=sess)

            elif cmd == "spo2":
                await send(client, CMDS["get_spo2"], sess=sess)

            elif cmd == "find":
                await send(client, CMDS["find_phone"], sess=sess)

            elif cmd == "ota":
                val = await read_char(client, CTRL_CHAR)
                if val:
                    sess.log("INFO", f"CTRL(0004) = {val.hex(' ')}", "I")
                else:
                    print(f"{C['W']}CTRL char not readable{C['X']}")

            elif cmd == "vib":
                if len(parts) > 1 and parts[1].lower() == "off":
                    await send(client, CMDS["vibrate_off"], sess=sess)
                else:
                    try:
                        n = int(parts[1]) if len(parts) > 1 else 1
                        n = max(0, min(n, 255))
                    except ValueError:
                        n = 1
                    pkt = bytes([0xCD, 0x00, 0x05, 0x1C, n, 0x04, 0x00, 0x00])
                    await send(client, pkt, sess=sess)

            elif cmd == "raw":
                if len(parts) < 2:
                    print("Usage: raw XX XX ...")
                else:
                    data = bytes(int(b, 16) for b in parts[1:])
                    await send(client, data, sess=sess)

            elif cmd == "ctrl":
                if len(parts) < 2:
                    print("Usage: ctrl XX XX ...")
                else:
                    data = bytes(int(b, 16) for b in parts[1:])
                    await send(client, data, char=CTRL_CHAR, sess=sess)

            elif cmd == "read":
                if len(parts) < 2:
                    print("Usage: read CHAR   (alias or full UUID)")
                else:
                    alias = parts[1].lower()
                    uuid  = CHAR_ALIASES.get(alias, alias)
                    val   = await read_char(client, uuid)
                    if val:
                        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in val)
                        sess.log("READ", f"{uuid[:8]}…  =  {val.hex(' ')}  │  {ascii_str}", "I")
                    else:
                        print(f"{C['W']}Could not read {uuid}{C['X']}")

            elif cmd == "probe":
                if len(parts) == 3:
                    start = int(parts[1], 16)
                    end   = int(parts[2], 16)
                else:
                    start, end = 0x00, 0xFF
                await brute_probe(client, sess, start, end)

            elif cmd == "probe2":
                if len(parts) < 2:
                    print("Usage: probe2 XX")
                else:
                    await probe2(client, sess, int(parts[1], 16))

            elif cmd == "probe3":
                if len(parts) < 3:
                    print("Usage: probe3 XX YY")
                else:
                    await probe3(client, sess, int(parts[1], 16), int(parts[2], 16))

            else:
                print(f"{C['W']}Unknown command: {line!r}.  Type 'help' for command list.{C['X']}")
                print(HELP)

        except BleakError as e:
            sess.log("ERROR", f"BLE error: {e}", "E")
        except ValueError as e:
            print(f"{C['E']}Bad input: {e}{C['X']}")
        except Exception as e:
            sess.log("ERROR", f"Unexpected: {type(e).__name__}: {e}", "E")


# ── Main connection loop with reconnect ───────────────────────────────────────
async def connect_and_run(address: Optional[str] = None) -> None:
    sess = Session()
    max_retries = 5
    backoff     = 2.0

    # If no target address was specified via arguments, open interactive menu
    if not address:
        address = await select_ble_device()

    for attempt in range(1, max_retries + 2):
        print(f"\n{C['I']}Connecting to {address} …{C['X']}")
        
        try:
            async with BleakClient(address, timeout=20.0) as client:
                print(f"{C['R']}● Connected  (attempt {attempt}){C['X']}\n")

                await client.start_notify(NOTIFY_CHAR, sess.on_notify)
                await client.start_notify(CTRL_CHAR,   sess.on_ctrl)
                await dump_device_info(client, sess)

                await repl(client, sess)

                try:
                    await client.stop_notify(NOTIFY_CHAR)
                    await client.stop_notify(CTRL_CHAR)
                except Exception:
                    pass
                break

        except BleakError as e:
            sess.log("ERROR", f"Connection error: {e}", "E")
            if attempt <= max_retries:
                wait = backoff * attempt
                print(f"{C['W']}Reconnecting in {wait:.0f}s…  (attempt {attempt}/{max_retries}){C['X']}")
                await asyncio.sleep(wait)
            else:
                print(f"{C['E']}Max retries reached. Giving up.{C['X']}")
                break

    if sess.log_entries:
        try:
            ans = input(f"\n{C['I']}Save session log? [y/N] {C['X']}").strip().lower()
            if ans == "y":
                path = sess.save()
                print(f"{C['I']}Saved → {path}  (+.json){C['X']}")
        except (EOFError, KeyboardInterrupt):
            pass


# ── Entry point ───────────────────────────────────────────────────────────────
async def main() -> None:
    print(BANNER)
    # Allows bypassing menu if directly executing `python tool.py AA:BB:CC:DD:EE:FF`
    addr = sys.argv[1] if len(sys.argv) > 1 else None
    await connect_and_run(addr)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{C['W']}Interrupted.{C['X']}")
