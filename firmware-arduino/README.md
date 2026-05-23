# Signet ESP32-S3 firmware (PlatformIO / Arduino)

Minimal firmware for the live demo: press the BOOT button on an
ESP32-S3-WROOM-1 dev kit, and the device fires an HTTP POST to the
Signet edge gateway. The gateway signs an ML-DSA-44 envelope on behalf
of the device and submits it to the verifier — the action lands in the
dashboard stream within a second.

The longer-form ESP-IDF firmware in `../firmware/` is the ESP32-C3 path
with on-device I²S audio capture. This Arduino project is the shorter,
safer path for the S3 hardware on the demo desk.

## Flash from VS Code (PlatformIO)

1. Open this folder (`firmware-arduino/`) in VS Code with the PlatformIO
   extension installed.
2. Copy `include/config.h.example` to `include/config.h` and fill in:
   - `WIFI_SSID` / `WIFI_PASS` — same network the laptop is on.
   - `GATEWAY_URL` — the laptop's LAN IP + `:8001/edge/trigger`
     (e.g. `http://192.168.1.42:8001/edge/trigger`).
3. Connect the ESP32-S3-WROOM-1 over USB-C.
4. PlatformIO toolbar → **Upload**. First flash builds the framework
   and takes ~2 min; reflashes are seconds.
5. PlatformIO toolbar → **Serial Monitor** to see `[signet] ready —
   press BOOT to fire an envelope`.

## Run the gateway alongside the verifier

```bash
# terminal 1 — verifier + dashboard
./start_demo.sh

# terminal 2 — edge gateway (signs on behalf of the device)
SIGNET_VERIFIER=http://127.0.0.1:8000 \
  .venv/bin/python scripts/edge_gateway.py --host 0.0.0.0 --port 8001
```

The gateway must listen on `0.0.0.0` (not the default 127.0.0.1) so the
device can reach it from the LAN. Note the LAN IP `ifconfig` shows for
your laptop and use that in `config.h`.

## What you'll see on stage

1. Press the BOOT button on the dev kit.
2. Onboard LED blinks once long → request succeeded.
3. Dashboard stream shows a new envelope: `agent_id = <gateway's
   device key>`, `action.name = button_press`, verified.

If the LED blinks four times short, the POST failed — check
`GATEWAY_URL`, the WiFi credentials, and that the gateway is reachable
from the device's WiFi network.

## TR-WS-2014B

This minimal firmware does **not** drive the TR-WS-2014B module. Once
the part is positively identified (digital MEMS microphone, analog
mic, sensor breakout, etc.) the I²S/ADC bring-up lives in a follow-up
revision.
