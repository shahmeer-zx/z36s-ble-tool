"""
WHOOP 5.0 BLE Recon & Control Tool
Based on community reverse-engineering of the WHOOP 4.0 protocol.
WHOOP 5.0 appears to use the same GATT service UUID family.

Key differences vs Z36s tool:
  - NOT a simple UART bridge — has 5 dedicated characteristics
  - Commands require proper framing: [cmd_id, seq, len_lo, len_hi, ...payload, crc32(4 bytes)]
  - Sequence counter increments per command (watch rejects dupes/out-of-order)
  - Real-time data is 96-byte packets with CRC-32 on last 4 bytes
  - Brute-force is limited by the framing requirement — we probe known cmd_ids

Sources:
  jogolden/whoomp        - UUIDs, command codes, packet structure
  bWanShiTong/openwhoop  - command/response codes, alarm, activity
  christianmeurer/whoop-reader - 96-byte packet field map
"""

from __future__ import annotations

import asyncio
import csv
import json
import struct
import sys
import zlib
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

try:
    from bleak import BleakClient, BleakError, BleakScanner
    from bleak.backends.characteristic import BleakGATTCharacteristic
except ImportError:
    print("bleak not found.  Run:  pip install bleak")
    sys.exit(1)

# ── ANSI colours ──────────────────────────────────────────────────────────────
C = {
    "R":   "\033[92m",    # green  – received
    "S":   "\033[94m",    # blue   – sent
    "E":   "\033[91m",    # red    – error
    "I":   "\033[93m",    # yellow – info/decoded
    "D":   "\033[96m",    # cyan   – debug
    "W":   "\033[95m",    # magenta – warning
    "X":   "\033[0m",     # reset
    "B":   "\033[1m",     # bold
    "DIM": "\033[2m",
}

BANNER = f"""{C['B']}{C['I']}
 ██╗    ██╗██╗  ██╗ ██████╗  ██████╗ ██████╗
 ██║    ██║██║  ██║██╔═══██╗██╔═══██╗██╔══██╗
 ██║ █╗ ██║███████║██║   ██║██║   ██║██████╔╝
 ██║███╗██║██╔══██║██║   ██║██║   ██║██╔═══╝
 ╚███╔███╔╝██║  ██║╚██████╔╝╚██████╔╝██║
  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝
{C['X']}{C['D']}  WHOOP 5.0 BLE Recon & Control Tool{C['X']}
"""

HELP = f"""
{C['B']}Commands:{C['X']}
  {C['I']}info{C['X']}               Dump GATT services + device info
  {C['I']}battery{C['X']}            Read battery level
  {C['I']}time{C['X']}               Sync phone time → watch
  {C['I']}hr{C['X']}                 Request heart-rate sample
  {C['I']}stream [N]{C['X']}         Stream live metrics (N seconds, default ∞)
  {C['I']}stream csv FILE{C['X']}    Stream and save to CSV
  {C['I']}alarm HH:MM{C['X']}        Set haptic alarm
  {C['I']}alarm off{C['X']}          Clear alarm
  {C['I']}raw CMD [XX ...]{C['X']}   Send framed command (hex cmd_id + optional payload)
  {C['I']}rawframe XX ...{C['X']}    Send completely raw bytes (no framing added)
  {C['I']}probe{C['X']}              Probe all known command IDs
  {C['I']}probe CMD{C['X']}          Probe single command ID with variants
  {C['I']}sniff{C['X']}              Listen on all chars, print everything
  {C['I']}read CHAR{C['X']}          Read a characteristic by alias or UUID
  {C['I']}watch{C['X']}              Toggle live notification dump
  {C['I']}save [FILE]{C['X']}        Save session log (JSON + txt)
  {C['I']}quit{C['X']}               Disconnect and exit
"""

# ── GATT UUIDs (confirmed for WHOOP 4.0; expected same on 5.0) ───────────────
# WHOOP 5.0 confirmed UUIDs (dumped live from device 5AG0748088)
WHOOP_SERVICE    = "fd4b0001-cce1-4033-93ce-002d5875f58a"

# Custom characteristics (fd4b service)
CMD_TO_STRAP     = "fd4b0002-cce1-4033-93ce-002d5875f58a"  # write/write-without-response → commands
RSP_FROM_STRAP   = "fd4b0003-cce1-4033-93ce-002d5875f58a"  # notify ← command responses
DATA_FROM_STRAP  = "fd4b0004-cce1-4033-93ce-002d5875f58a"  # notify ← realtime data stream
EVENTS_FROM_STRAP= "fd4b0005-cce1-4033-93ce-002d5875f58a"  # notify ← device events
DIAG_TO_STRAP    = "fd4b0007-cce1-4033-93ce-002d5875f58a"  # notify ← diagnostics (fd4b0006 absent)

# Standard BLE Heart Rate service (confirmed on 5.0 — broadcasts HR natively)
HR_MEASUREMENT   = "00002a37-0000-1000-8000-00805f9b34fb"  # notify ← HR + RR intervals

# Standard characteristics
BATTERY_CHAR     = "00002a19-0000-1000-8000-00805f9b34fb"
DIS_CHARS = {
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software",
}

CHAR_ALIASES = {
    "cmd":    CMD_TO_STRAP,
    "rsp":    RSP_FROM_STRAP,
    "data":   DATA_FROM_STRAP,
    "events": EVENTS_FROM_STRAP,
    "diag":   DIAG_TO_STRAP,
    "batt":   BATTERY_CHAR,
    "battery":BATTERY_CHAR,
}

# ── Known command IDs (from community RE of WHOOP 4.0 firmware) ───────────────
# Format: cmd_id → (name, default_payload_bytes)
KNOWN_CMDS: Dict[int, Tuple[str, bytes]] = {
    0x07: ("get_battery",      b""),
    0x08: ("start_realtime",   b""),
    0x09: ("stop_realtime",    b""),
    0x0A: ("get_device_info",  b""),
    0x0B: ("set_time",         b""),   # payload built dynamically
    0x0C: ("get_time",         b""),
    0x0D: ("set_alarm",        b""),   # payload built dynamically
    0x0E: ("clear_alarm",      b""),
    0x0F: ("get_alarm",        b""),
    0x10: ("start_activity",   b""),
    0x11: ("stop_activity",    b""),
    0x14: ("get_heart_rate",   b""),
    0x15: ("get_hrv",          b""),
    0x20: ("get_history",      b""),
    0x25: ("ota_begin",        b""),
    0x28: ("factory_reset",    b""),   # DO NOT PROBE
}

UNSAFE_CMDS = {0x28}   # never auto-probe these

# ── Packet framing ─────────────────────────────────────────────────────────────
#
# WHOOP command frame format (confirmed from whoomp/openwhoop RE):
#   [0]     cmd_id      uint8
#   [1]     seq         uint8  (increments per command, wraps at 255)
#   [2:4]   payload_len uint16 little-endian
#   [4:]    payload     bytes  (0 or more)
#   [-4:]   crc32       uint32 little-endian  (zlib.crc32 of all preceding bytes)
#
# The watch validates seq and crc32. Wrong crc32 → no response.
# seq mismatch → watch may ignore or send error.

def build_frame(cmd_id: int, seq: int, payload: bytes = b"") -> bytes:
    header = struct.pack("<BBH", cmd_id, seq, len(payload))
    body   = header + payload
    crc    = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack("<I", crc)


def verify_frame(data: bytes) -> bool:
    """Return True if the last 4 bytes are valid CRC-32 of the preceding bytes."""
    if len(data) < 8:
        return False
    body, crc_bytes = data[:-4], data[-4:]
    expected = zlib.crc32(body) & 0xFFFFFFFF
    received = struct.unpack_from("<I", crc_bytes)[0]
    return expected == received


# ── 96-byte real-time packet parser ───────────────────────────────────────────
#
# Field map from christianmeurer/whoop-reader + bWanShiTong RE:
#   [0:2]   packet_seq  uint16
#   [2:4]   timestamp   uint16  (seconds since last sync, or relative)
#   [4]     hr_bpm      uint8
#   [5:7]   rr_ms       uint16  (R-R interval in ms — instantaneous HRV)
#   [7]     spo2        uint8   (%)
#   [8]     skin_temp   int8    (°C, signed, add offset — calibration dependent)
#   [9:12]  accel_x     int16   (raw ADC, little-endian)  ← candidate/unconfirmed
#   [11:13] accel_y     int16
#   [13:15] accel_z     int16
#   [15]    motion      uint8   (motion intensity, 0-255)
#   [16:18] ppg_amp     uint16  (PPG amplitude / green LED)
#   [18:20] ambient     uint16  (ambient light ADC)
#   [20:92] unknown     bytes   (likely gyro, red LED, respiration, waveform samples)
#   [92:96] crc32       uint32  little-endian  (crc of [0:92])

RealtimePacket = dict

def parse_realtime(data: bytes) -> Optional[RealtimePacket]:
    if len(data) != 96:
        return None

    # Verify CRC
    crc_ok = (zlib.crc32(data[:92]) & 0xFFFFFFFF) == struct.unpack_from("<I", data, 92)[0]

    pkt_seq  = struct.unpack_from("<H", data, 0)[0]
    ts       = struct.unpack_from("<H", data, 2)[0]
    hr       = data[4]
    rr       = struct.unpack_from("<H", data, 5)[0]
    spo2     = data[7]
    temp_raw = struct.unpack_from("b", data, 8)[0]   # signed
    # Raw accel (unconfirmed field positions)
    ax       = struct.unpack_from("<h", data, 9)[0]
    ay       = struct.unpack_from("<h", data, 11)[0]
    az       = struct.unpack_from("<h", data, 13)[0]
    motion   = data[15]
    ppg_amp  = struct.unpack_from("<H", data, 16)[0]
    ambient  = struct.unpack_from("<H", data, 18)[0]
    unknown  = data[20:92].hex(" ")

    return {
        "seq":      pkt_seq,
        "ts":       ts,
        "hr":       hr,
        "rr_ms":    rr,
        "spo2":     spo2,
        "temp_c":   temp_raw,          # raw — needs calibration offset
        "accel":    (ax, ay, az),      # unconfirmed
        "motion":   motion,
        "ppg_amp":  ppg_amp,
        "ambient":  ambient,
        "unknown":  unknown,
        "crc_ok":   crc_ok,
        "raw_hex":  data.hex(" "),
        "wall_time": datetime.now().isoformat(timespec="milliseconds"),
    }


# ── Session ───────────────────────────────────────────────────────────────────
class Session:
    def __init__(self) -> None:
        self.seq: int = 0
        self.log_entries: list[dict] = []
        self.realtime_packets: list[RealtimePacket] = []
        self.live_watch = True
        self._rsp_queue: asyncio.Queue = asyncio.Queue()
        self._streaming = False
        self._stream_cb: Optional[Callable[[RealtimePacket], None]] = None

    def next_seq(self) -> int:
        s = self.seq
        self.seq = (self.seq + 1) & 0xFF
        return s

    def ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def log(self, tag: str, msg: str, color: str = "") -> None:
        entry = {"t": self.ts(), "tag": tag, "msg": msg}
        self.log_entries.append(entry)
        if self.live_watch or tag in ("ERROR", "DECODE", "INFO", "WARN"):
            print(f"{C.get(color, '')}[{entry['t']}] [{tag:<6}] {msg}{C['X']}")

    # ── notification handlers ─────────────────────────────────────────────────
    def on_rsp(self, sender: BleakGATTCharacteristic, data: bytearray) -> None:
        hex_str = data.hex(" ")
        crc_ok = verify_frame(bytes(data))
        suffix = f"  {C['I']}[CRC {'OK' if crc_ok else 'FAIL'}]{C['X']}" if len(data) >= 8 else ""
        self.log("RSP", f"{hex_str}{suffix}", "R")
        self._rsp_queue.put_nowait(bytes(data))
        self._decode_rsp(bytes(data))

    def on_data(self, sender: BleakGATTCharacteristic, data: bytearray) -> None:
        if len(data) == 96:
            pkt = parse_realtime(bytes(data))
            if pkt:
                self.realtime_packets.append(pkt)
                if self.live_watch or self._streaming:
                    crc = f"{C['I']}✓{C['X']}" if pkt["crc_ok"] else f"{C['E']}✗{C['X']}"
                    hr_bar = "♥ " * min(pkt["hr"] // 20, 8)
                    self.log("DATA",
                        f"HR={pkt['hr']:>3}bpm  RR={pkt['rr_ms']:>4}ms  "
                        f"SpO₂={pkt['spo2']:>3}%  Temp={pkt['temp_c']:+d}°C  "
                        f"Motion={pkt['motion']:>3}  CRC={crc}  {C['DIM']}{hr_bar}{C['X']}",
                        "D")
                if self._stream_cb:
                    self._stream_cb(pkt)
        else:
            self.log("DATA", f"({len(data)}B) {data.hex(' ')}", "R")

    def on_events(self, sender: BleakGATTCharacteristic, data: bytearray) -> None:
        self.log("EVENT", data.hex(" "), "W")

    def on_hr_standard(self, sender: BleakGATTCharacteristic, data: bytearray) -> None:
        """Parse standard BLE Heart Rate Measurement characteristic (0x2a37).
        Byte 0 flags: bit0=uint16 HR, bit4=RR present
        """
        if not data:
            return
        flags  = data[0]
        offset = 1
        if flags & 0x01:
            hr = struct.unpack_from("<H", data, offset)[0]; offset += 2
        else:
            hr = data[offset]; offset += 1
        rr_intervals = []
        if flags & 0x10:
            while offset + 1 < len(data):
                rr_raw = struct.unpack_from("<H", data, offset)[0]; offset += 2
                rr_intervals.append(round(rr_raw / 1024 * 1000))  # 1/1024s → ms
        rr_str = f"  RR={rr_intervals}ms" if rr_intervals else ""
        self.log("HR", f"{hr} bpm{rr_str}", "R")

    def _decode_rsp(self, data: bytes) -> None:
        if len(data) < 4:
            return
        cmd_id = data[0]
        seq    = data[1]
        pay_len = struct.unpack_from("<H", data, 2)[0]
        payload = data[4: 4 + pay_len]

        name = KNOWN_CMDS.get(cmd_id, (f"cmd_{cmd_id:#04x}", None))[0]
        self.log("DECODE", f"Response to {name} (seq={seq})", "I")

        if cmd_id == 0x07 and len(payload) >= 1:    # battery
            self.log("DECODE", f"Battery → {payload[0]}%", "I")

        elif cmd_id == 0x0B and len(payload) >= 6:  # time ack
            y, mo, d, h, mi, s = payload[:6]
            self.log("DECODE", f"Time ack → 20{y:02d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}", "I")

        elif cmd_id == 0x0A and len(payload) >= 4:  # device info
            text = payload.decode("utf-8", errors="replace").rstrip("\x00")
            self.log("DECODE", f"Device info → {text}", "I")

        elif cmd_id == 0x14 and len(payload) >= 1:  # heart rate
            self.log("DECODE", f"Heart rate → {payload[0]} bpm", "I")

    async def wait_rsp(self, timeout: float = 3.0) -> Optional[bytes]:
        try:
            return await asyncio.wait_for(self._rsp_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def save(self, path: Optional[str] = None) -> Path:
        stem = path or f"whoop_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        Path(stem + ".json").write_text(
            json.dumps({"log": self.log_entries, "realtime": self.realtime_packets}, indent=2)
        )
        Path(stem + ".txt").write_text(
            "\n".join(f"[{e['t']}] [{e['tag']:<6}] {e['msg']}" for e in self.log_entries)
        )
        if self.realtime_packets:
            with open(stem + "_realtime.csv", "w", newline="") as f:
                fields = ["wall_time","seq","ts","hr","rr_ms","spo2","temp_c",
                          "motion","ppg_amp","ambient","crc_ok"]
                w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                w.writerows(self.realtime_packets)
            print(f"{C['I']}  + realtime CSV → {stem}_realtime.csv{C['X']}")
        return Path(stem + ".txt")


# ── BLE send helpers ──────────────────────────────────────────────────────────
async def send_cmd(client: BleakClient, sess: Session,
                   cmd_id: int, payload: bytes = b"",
                   wait_rsp: bool = True) -> Optional[bytes]:
    """Build a properly framed command, send it, optionally wait for response."""
    seq   = sess.next_seq()
    frame = build_frame(cmd_id, seq, payload)
    name  = KNOWN_CMDS.get(cmd_id, (f"cmd_{cmd_id:#04x}", None))[0]
    sess.log("SENT", f"{name} (seq={seq})  frame: {frame.hex(' ')}", "S")
    await client.write_gatt_char(CMD_TO_STRAP, bytearray(frame), response=True)
    if wait_rsp:
        rsp = await sess.wait_rsp(timeout=3.0)
        if rsp is None:
            sess.log("WARN", f"No response to {name} (seq={seq})", "W")
        return rsp
    return None


async def read_char(client: BleakClient, uuid: str) -> Optional[bytes]:
    try:
        return bytes(await client.read_gatt_char(uuid))
    except Exception:
        return None


# ── High-level commands ───────────────────────────────────────────────────────
async def dump_info(client: BleakClient, sess: Session) -> None:
    print(f"\n{C['B']}─── GATT Device Information {'─'*30}{C['X']}")
    for uuid, name in DIS_CHARS.items():
        val = await read_char(client, uuid)
        if val:
            text = val.decode("utf-8", errors="replace").rstrip("\x00")
            print(f"  {name:<14}: {C['I']}{text}{C['X']}  {C['DIM']}({val.hex(' ')}){C['X']}")
        else:
            print(f"  {name:<14}: {C['DIM']}(not available){C['X']}")

    batt = await read_char(client, BATTERY_CHAR)
    if batt:
        lvl = batt[0]
        bar = "█" * (lvl // 10) + "░" * (10 - lvl // 10)
        print(f"  {'Battery':<14}: {C['I']}{lvl}%{C['X']}  [{bar}]")

    print(f"\n{C['B']}─── WHOOP Protocol Commands {'─'*32}{C['X']}")
    await send_cmd(client, sess, 0x0A)   # get_device_info
    await send_cmd(client, sess, 0x07)   # get_battery
    print(f"{C['B']}{'─'*58}{C['X']}\n")


async def set_time(client: BleakClient, sess: Session) -> None:
    now = datetime.now()
    payload = struct.pack("BBBBBB",
        now.year % 100, now.month, now.day,
        now.hour, now.minute, now.second)
    await send_cmd(client, sess, 0x0B, payload)
    sess.log("INFO", f"Time sync → {now.strftime('%Y-%m-%d %H:%M:%S')}", "I")


async def set_alarm(client: BleakClient, sess: Session, hour: int, minute: int) -> None:
    # Alarm payload: HH MM (2 bytes) — from bWanShiTong openwhoop RE
    payload = struct.pack("BB", hour, minute)
    await send_cmd(client, sess, 0x0D, payload)
    sess.log("INFO", f"Alarm set → {hour:02d}:{minute:02d}", "I")


async def stream_realtime(client: BleakClient, sess: Session,
                          duration: Optional[float] = None,
                          csv_path: Optional[str] = None) -> None:
    csv_file = None
    csv_writer = None
    fields = ["wall_time","seq","ts","hr","rr_ms","spo2","temp_c",
              "motion","ppg_amp","ambient","crc_ok"]

    if csv_path:
        csv_file = open(csv_path, "w", newline="")
        csv_writer = csv.DictWriter(csv_file, fieldnames=fields, extrasaction="ignore")
        csv_writer.writeheader()
        sess.log("INFO", f"Streaming to CSV → {csv_path}", "I")

    if csv_writer:
        def _cb(pkt: RealtimePacket):
            csv_writer.writerow({k: pkt[k] for k in fields})
            csv_file.flush()
        sess._stream_cb = _cb

    sess._streaming = True
    sess.log("INFO", "Starting real-time stream (Ctrl+C to stop)…", "I")
    await send_cmd(client, sess, 0x08, wait_rsp=False)   # start_realtime

    try:
        if duration:
            await asyncio.sleep(duration)
        else:
            while True:
                await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        sess._streaming = False
        sess._stream_cb = None
        await send_cmd(client, sess, 0x09, wait_rsp=False)   # stop_realtime
        sess.log("INFO", f"Stream stopped. {len(sess.realtime_packets)} packets captured.", "I")
        if csv_file:
            csv_file.close()


# ── Probe ─────────────────────────────────────────────────────────────────────
async def probe_cmds(client: BleakClient, sess: Session,
                     target: Optional[int] = None) -> None:
    """Send each known command ID with empty payload and record responses."""
    cmds = [(cid, name) for cid, (name, _) in KNOWN_CMDS.items()
            if cid not in UNSAFE_CMDS]
    if target is not None:
        cmds = [(cid, name) for cid, name in cmds if cid == target]
        if not cmds:
            print(f"{C['W']}Unknown or unsafe command ID {target:#04x}{C['X']}")
            return

    print(f"\n{C['B']}── Probing {len(cmds)} command IDs {'─'*34}{C['X']}")
    hits = []
    for cmd_id, name in cmds:
        print(f"  {C['D']}→ {name} ({cmd_id:#04x}){C['X']}", end="  ", flush=True)
        rsp = await send_cmd(client, sess, cmd_id)
        if rsp:
            hits.append((cmd_id, name, rsp))
            print(f"{C['R']}← {rsp.hex(' ')[:48]}{C['X']}")
        else:
            print(f"{C['DIM']}(no response){C['X']}")
        await asyncio.sleep(0.3)

    print(f"\n{C['B']}── Results: {len(hits)}/{len(cmds)} responded {'─'*28}{C['X']}")
    for cmd_id, name, rsp in hits:
        print(f"  {cmd_id:#04x}  {name:<20}  {rsp.hex(' ')[:60]}")
    print(f"{C['B']}{'─'*58}{C['X']}\n")


# ── Async input ───────────────────────────────────────────────────────────────
async def async_input(prompt: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: input(prompt))


# ── REPL ──────────────────────────────────────────────────────────────────────
async def repl(client: BleakClient, sess: Session) -> None:
    print(HELP)

    while True:
        try:
            line = (await async_input(f"{C['B']}whoop>{C['X']} ")).strip()
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
                await dump_info(client, sess)

            elif cmd == "battery":
                await send_cmd(client, sess, 0x07)

            elif cmd == "time":
                await set_time(client, sess)

            elif cmd == "hr":
                await send_cmd(client, sess, 0x14)

            elif cmd == "stream":
                # stream [N] | stream csv FILE
                duration  = None
                csv_path  = None
                if len(parts) >= 2 and parts[1].lower() == "csv":
                    csv_path = parts[2] if len(parts) > 2 else \
                        f"whoop_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                elif len(parts) >= 2:
                    try:
                        duration = float(parts[1])
                    except ValueError:
                        pass
                await stream_realtime(client, sess, duration, csv_path)

            elif cmd == "alarm":
                if len(parts) > 1 and parts[1].lower() == "off":
                    await send_cmd(client, sess, 0x0E)
                elif len(parts) > 1 and ":" in parts[1]:
                    h, m = (int(x) for x in parts[1].split(":"))
                    await set_alarm(client, sess, h, m)
                else:
                    print("Usage: alarm HH:MM  |  alarm off")

            elif cmd == "raw":
                if len(parts) < 2:
                    print("Usage: raw CMD_ID_HEX [payload hex bytes ...]")
                else:
                    cmd_id  = int(parts[1], 16)
                    payload = bytes(int(b, 16) for b in parts[2:]) if len(parts) > 2 else b""
                    await send_cmd(client, sess, cmd_id, payload)

            elif cmd == "rawframe":
                if len(parts) < 2:
                    print("Usage: rawframe XX XX XX ...")
                else:
                    data = bytes(int(b, 16) for b in parts[1:])
                    sess.log("SENT", f"RAW {data.hex(' ')}", "S")
                    await client.write_gatt_char(CMD_TO_STRAP, bytearray(data), response=True)

            elif cmd == "probe":
                target = int(parts[1], 16) if len(parts) > 1 else None
                await probe_cmds(client, sess, target)

            elif cmd == "sniff":
                sess.live_watch = True
                print(f"{C['I']}Listening on all channels. Press Enter to stop.{C['X']}")
                await async_input("")

            elif cmd == "read":
                if len(parts) < 2:
                    print("Usage: read CHAR   (alias or UUID)")
                else:
                    alias = parts[1].lower()
                    uuid  = CHAR_ALIASES.get(alias, alias)
                    val   = await read_char(client, uuid)
                    if val:
                        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in val)
                        sess.log("READ", f"{alias} = {val.hex(' ')}  │  {ascii_str}", "I")
                    else:
                        print(f"{C['W']}Could not read {uuid}{C['X']}")

            elif cmd == "watch":
                sess.live_watch = not sess.live_watch
                print(f"{C['I']}Live dump: {'ON' if sess.live_watch else 'OFF'}{C['X']}")

            elif cmd == "save":
                p = parts[1] if len(parts) > 1 else None
                saved = sess.save(p)
                print(f"{C['I']}Saved → {saved}  (+.json){C['X']}")

            else:
                print(f"{C['W']}Unknown command: {line!r}{C['X']}")
                print(HELP)

        except BleakError as e:
            sess.log("ERROR", f"BLE error: {e}", "E")
        except ValueError as e:
            print(f"{C['E']}Bad input: {e}{C['X']}")
        except Exception as e:
            sess.log("ERROR", f"{type(e).__name__}: {e}", "E")


# ── Connection loop ───────────────────────────────────────────────────────────
async def connect_and_run(address: Optional[str] = None) -> None:
    sess = Session()
    max_retries = 5

    for attempt in range(1, max_retries + 2):
        if address:
            print(f"\n{C['I']}Connecting to {address} …{C['X']}")
            device = address
        else:
            print(f"\n{C['I']}Scanning for WHOOP…{C['X']}")
            device = await BleakScanner.find_device_by_filter(
                lambda d, ad: bool(
                    (d.name and "WHOOP" in d.name.upper()) or
                    # WHOOP sometimes advertises with service UUID only, no name
                    (ad.service_uuids and
                     any(WHOOP_SERVICE.lower() in u.lower() for u in ad.service_uuids))
                ),
                timeout=15.0,
            )
            if not device:
                print(f"{C['E']}WHOOP not found.\n"
                      f"  • Make sure the WHOOP app is closed (it holds the BLE connection)\n"
                      f"  • Try passing the MAC/UUID as a CLI argument: python whoop_ble.py AA:BB:CC:DD:EE:FF{C['X']}")
                sys.exit(1)
            address = device.address
            name = getattr(device, "name", "WHOOP")
            print(f"{C['I']}Found: {name}  [{device.address}]{C['X']}")

        try:
            async with BleakClient(device, timeout=20.0) as client:
                print(f"\033[92m Connected (attempt {attempt})\033[0m\n")

                # ── Dump ALL services and characteristics ─────────────
                print(f"\033[1m--- Raw GATT Map ---\033[0m")
                found_chars: Dict[str, str] = {}
                for svc in client.services:
                    print(f"  SVC  {svc.uuid}  {svc.description or ''}")
                    for char in svc.characteristics:
                        props = ",".join(char.properties)
                        print(f"    CHAR {char.uuid}  [{props}]")
                        found_chars[char.uuid.lower()] = props
                        for desc in char.descriptors:
                            print(f"      DESC {desc.uuid}")
                print()

                # ── Subscribe only to chars that exist + support notify ─
                notify_map = {
                    RSP_FROM_STRAP:    sess.on_rsp,
                    DATA_FROM_STRAP:   sess.on_data,
                    EVENTS_FROM_STRAP: sess.on_events,
                    HR_MEASUREMENT:    sess.on_hr_standard,  # standard BLE HR service
                }
                subscribed = []
                for uuid, handler in notify_map.items():
                    props = found_chars.get(uuid.lower(), "")
                    if "notify" in props or "indicate" in props:
                        try:
                            await client.start_notify(uuid, handler)
                            subscribed.append(uuid)
                            sess.log("INFO", f"Subscribed -> {uuid}", "I")
                        except Exception as e:
                            sess.log("WARN", f"Subscribe failed {uuid}: {e}", "W")
                    elif uuid.lower() in found_chars:
                        sess.log("WARN", f"{uuid} exists but no notify ({props})", "W")

                # Also recon-subscribe to any unknown notifiable chars
                known_uuids = {u.lower() for u in notify_map}
                for uuid, props in found_chars.items():
                    if uuid not in known_uuids and ("notify" in props or "indicate" in props):
                        try:
                            def _make_handler(u: str):
                                def _h(sender, data: bytearray):
                                    sess.log("RECON", f"{u[:8]}... {data.hex(' ')}", "W")
                                return _h
                            await client.start_notify(uuid, _make_handler(uuid))
                            sess.log("INFO", f"Recon-subscribed -> {uuid}", "D")
                        except Exception:
                            pass

                # Auto-dump on connect
                await dump_info(client, sess)
                await set_time(client, sess)

                await repl(client, sess)

                for uuid in list(subscribed):
                    try:
                        await client.stop_notify(uuid)
                    except Exception:
                        pass
                break


        except BleakError as e:
            err = str(e)
            sess.log("ERROR", f"{e}", "E")
            if "Characteristic" in err or "not found" in err.lower():
                # Protocol mismatch — retrying won't help, drop straight to REPL
                print(f"{C['W']}Characteristic error — check UUID map. Dropping to shell.{C['X']}")
                break
            if attempt <= max_retries:
                wait = 2.0 * attempt
                print(f"{C['W']}Reconnecting in {wait:.0f}s...{C['X']}")
                await asyncio.sleep(wait)
            else:
                print(f"{C['E']}Max retries reached.{C['X']}")
                break

    if sess.log_entries:
        try:
            ans = input(f"\n{C['I']}Save session log? [y/N] {C['X']}").strip().lower()
            if ans == "y":
                saved = sess.save()
                print(f"{C['I']}Saved → {saved}{C['X']}")
        except (EOFError, KeyboardInterrupt):
            pass


async def main() -> None:
    print(BANNER)
    addr = sys.argv[1] if len(sys.argv) > 1 else None
    await connect_and_run(addr)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{C['W']}Interrupted.{C['X']}")
