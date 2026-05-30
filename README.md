# 🛰️ Z36s BLE Recon & Control Tool

A Python-based Bluetooth Low Energy (BLE) reverse engineering and interaction framework designed for analyzing, probing, and interacting with DA14583-class wearable devices (such as LB726-series smartwatches).

This tool provides a full interactive shell for BLE communication, command testing, device probing, and live packet analysis.

---

# ⚡ Overview

Z36s is built for BLE protocol research and wearable device analysis. It enables:

- Device discovery and selection
- GATT characteristic interaction
- Live notification decoding
- Command injection and raw packet sending
- Brute-force probing of unknown commands
- Real-time session logging
- Device feature exploration (HR, BP, SpO2, steps, vibration, etc.)

---

# 🚀 Key Features

## 📡 BLE Device Management
- Automatic scanning of nearby BLE devices
- Interactive device selection menu
- RSSI-based sorting for stronger signal prioritization
- Robust reconnection handling

---

## 🔬 Device Interaction
- Read/write GATT characteristics
- Battery level reading
- Device metadata extraction (firmware, model, manufacturer)
- Time synchronization with device

---

## ❤️ Health Data Requests
Supports common wearable sensor queries:
- Step counter
- Heart rate
- Blood pressure
- SpO2 oxygen levels

---

## 📳 Control Features
- Vibration control (multi-pulse support)
- Stop vibration command
- Find-my-phone trigger
- OTA/control channel inspection

---

## 🧪 Reverse Engineering Tools
- Raw hex packet sender
- Single-byte brute-force probing
- Multi-byte command space exploration
- Response capture mapping
- Unknown command discovery

---

## 📊 Live Monitoring
- Real-time BLE notification stream
- ASCII + HEX decoding
- Automatic command response parsing
- Structured logging system

---

## 💾 Session Logging
Each session can be saved as:
- JSON structured logs
- Human-readable TXT logs

Includes:
- timestamps
- sent packets
- received notifications
- decoded values

---

# 🧠 How It Works

Z36s interacts with BLE devices using a Nordic UART-style service structure:

- WRITE Characteristic → Send commands
- NOTIFY Characteristic → Receive responses
- CTRL Characteristic → Device state control

It decodes responses using a reverse-engineered packet structure from DA14583-based devices.

---

# 🖥️ Requirements

- Python 3.8+
- macOS / Linux / Windows (BLE capable adapter required)

---

# 📦 Installation

Clone the repository:

```bash id="install1"
git clone https://github.com/shahmeer-zx/z36s-ble-tool.git
cd z36s-ble-tool
