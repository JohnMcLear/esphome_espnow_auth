# ESPHome ESP-NOW Auth

An [ESPHome](https://esphome.io) external component that adds **HMAC-SHA256 challenge-response authentication** to ESP-NOW between ESP32 devices.

ESP-NOW is connectionless and has no authentication of its own: any device on the channel can inject frames. With this component an `outside` node must prove it holds a pre-shared key before the `inside` node will serve it.

## Status

- CI (on pushes and pull requests to `main`, ESPHome 2026.10.0): compiles 4 configs (outside, inside, and both with `wifi:` present), runs the config validation tests (`tests/test_config_validation.py`), and checks formatting with black and isort.
- Not proven on hardware: there are no published hardware logs. The handshake, Wi-Fi coexistence, standalone mode and channel following are covered only by compiles.

Requirements: ESPHome 2026.10.0 (the version CI pins), Arduino framework, ESP32 (CI builds for `esp32dev`). Other frameworks and chip variants are untested.

## How it works

```
Outside (untrusted)              Inside (trusted)
        ── AUTH_REQUEST ──────────►
        ◄── AUTH_CHALLENGE(nonce) ──
        ── AUTH_RESPONSE(nonce, HMAC-SHA256) ──►
                                   verify HMAC
        ◄── AUTH_OK ───────────────
        ── PING ──────────────────►  (accepted)
        ◄── PONG ─────────────────
```

1. **Outside** sends `AUTH_REQUEST` on boot and retries every 5 s until authorised.
2. **Inside** generates a 16-byte nonce from the hardware RNG (`esp_random`) and sends `AUTH_CHALLENGE`.
3. **Outside** computes HMAC-SHA256 over the nonce, keyed with `shared_key`, and replies with `AUTH_RESPONSE`.
4. **Inside** checks the nonce and the HMAC (constant-time comparison) and sends `AUTH_OK` or `AUTH_FAIL`.
5. Only authorised MAC addresses get ping/pong service. An unanswered challenge expires after 10 s. The inside node tracks up to 4 peers.

Crypto is provided by mbedtls, which ships with ESP-IDF.

## Installation

```yaml
external_components:
  - source: github://JohnMcLear/esphome_espnow_auth
    components: [espnow_auth]
```

A local checkout works too: `source: { type: local, path: path/to/esphome_espnow_auth/components }`.

## Quick start

Create a `secrets.yaml` next to your config files:

```yaml
wifi_ssid: "YourNetwork"
wifi_password: "YourPassword"
espnow_key: "your-shared-secret-here"
```

```yaml
# outside.yaml
esphome:
  name: outside-node

esp32:
  board: esp32dev
  framework:
    type: arduino

external_components:
  - source: github://JohnMcLear/esphome_espnow_auth
    components: [espnow_auth]

logger:
  baud_rate: 115200

wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password
  reboot_timeout: 0s
  fast_connect: true

api:

ota:
  platform: esphome

espnow_auth:
  role: outside
  shared_key: !secret espnow_key
```

```yaml
# inside.yaml: the same, with role: inside
espnow_auth:
  role: inside
  shared_key: !secret espnow_key
```

Complete configs are in `examples/`.

## Configuration

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `role` | yes | | `outside` (untrusted, starts the handshake) or `inside` (trusted, verifies it) |
| `shared_key` | yes | | Pre-shared secret for HMAC-SHA256. Must match on both nodes. |
| `channel` | no | `1` | Wi-Fi channel (1-14) for ESP-NOW. Only used in standalone mode (no `wifi:` block). |

## Wi-Fi coexistence

When a `wifi:` block is present, the component runs ESP-NOW on top of ESPHome's Wi-Fi stack, so OTA updates, the Home Assistant API and `web_server:` keep working. ESP-NOW then uses whatever channel the access point is on, so both nodes must join the same network.

Pin the access point to a fixed channel. If it changes channel, nodes on Wi-Fi follow it but standalone nodes do not.

## Standalone mode

Without a `wifi:` block the component brings up the radio itself. All nodes must use the same `channel`, and updates need USB.

## Flashing

First flash over USB:

```bash
esphome run outside.yaml --device /dev/ttyUSB0
esphome run inside.yaml  --device /dev/ttyUSB1
```

After that, with a `wifi:` block present, flash over the network:

```bash
esphome run outside.yaml  # finds outside-node.local
esphome run inside.yaml   # finds inside-node.local
```

## Security notes

- The `shared_key` is compiled into the firmware as a plain string. Use `!secret` and keep `secrets.yaml` out of version control. For stronger protection, enable [ESP32 flash encryption](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/flash-encryption.html).
- HMAC verification uses a constant-time comparison.
- Each challenge uses a fresh hardware-RNG nonce and must be answered within 10 s, so a recorded handshake response cannot be replayed.
- ESP-NOW frames are not encrypted at the radio level. This component authenticates peers; it does not encrypt payloads.
- Only the handshake is authenticated. Once a peer is authorised, later messages from it are accepted on its MAC address alone, and a MAC address can be spoofed. Authorisation lasts until the inside node restarts. Do not use the authorised state on its own to gate anything security-relevant, such as an unlock; authenticate that message too.
- Authentication is one-way: the inside node verifies the outside node, but `AUTH_OK`, `AUTH_FAIL` and `PONG` are unauthenticated broadcasts, so the outside node cannot tell a genuine inside node from an impostor.

## Licence

MIT, see `LICENSE`.
