# Signet ESP32-C3 Edge Firmware

Reference firmware for the **edge agent** Plan-B path (voice trigger over I²S
audio). The primary device on the demo desk is the ESP32-S3 in
`../firmware-arduino/` — this ESP-IDF firmware is the fallback.

## What this does

The ESP32-C3 acts as a voice-activated agent endpoint. Loop:

1. Connect to Wi-Fi.
2. Capture 16 kHz mono audio over I²S from a TRWS2014B (or equivalent) mic.
3. Apply a 200 ms energy-threshold trigger (full ASR is out of scope for the
   firmware tier). On trigger, build a JSON payload with an audio fingerprint and
   POST it to the **edge gateway** (`scripts/edge_gateway.py`).
4. The gateway holds a registered ML-DSA-44 device identity, signs a Signet
   envelope on the device's behalf, and submits to the verifier.

This is the **gateway-side-signing** path: if the pqm4 RISC-V Dilithium port
doesn't build for `esp32c3`, the device just sends an audio fingerprint and the
gateway signs. The cryptography (ML-DSA-44 sign/verify) is identical in both
paths — only the host of the signing key differs. On-device signing is the
Phase 2 upgrade.

## Layout

```
firmware/
├── CMakeLists.txt                  ESP-IDF project root
├── sdkconfig.defaults              Default config (Wi-Fi credentials, I²S, log level)
├── main/
│   ├── CMakeLists.txt
│   └── main.c                      I²S capture, trigger, HTTP POST
└── README.md                       this file
```

## Build & flash

```bash
# Requires ESP-IDF 5.3+ (https://docs.espressif.com/projects/esp-idf/en/v5.3/esp32c3/)
cd firmware
idf.py set-target esp32c3
idf.py menuconfig         # Set Wi-Fi SSID, password, and gateway URL
idf.py build
idf.py -p /dev/cu.usbserial-XXXX flash monitor
```

## Demo path without hardware

If the C3 is not present at demo time, the gateway can be driven by the
emulator script:

```bash
python scripts/simulate_edge_device.py --triggers 1
```

That sends one synthetic "voice trigger" to the gateway and produces an
envelope on the dashboard exactly as the real device would. The dashboard
cannot tell the difference — the envelope's `action.params.source` is set to
`"esp32c3"` in both cases.
