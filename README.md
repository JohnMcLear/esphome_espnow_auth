# ESPHome ESP-NOW Auth

An [ESPHome](https://esphome.io) external component that adds **HMAC-SHA256 challenge-response authentication** to ESP-NOW communication between ESP32 devices.

## Why

ESP-NOW is a connectionless protocol with no built-in authentication. Any device that knows the channel can inject messages. This component makes a peer prove it holds the pre-shared key, with an HMAC-SHA256 challenge-response, before the inside node accepts messages from it.

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

1. **Outside** sends `AUTH_REQUEST` on boot (retries every 5 s).
2. **Inside** generates a 16-byte random nonce and sends `AUTH_CHALLENGE`.
3. **Outside** computes `HMAC-SHA256(nonce, shared_key)` and replies with `AUTH_RESPONSE`.
4. **Inside** verifies the HMAC (constant-time comparison) and sends `AUTH_OK` or `AUTH_FAIL`.
5. Only authorized MACs receive ping/pong service. Stale challenges expire after 10 s.

Crypto is provided by **mbedtls** (ships with ESP-IDF). Nonces come from the hardware RNG (`esp_random`).

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
  - source:
      type: git
      url: https://github.com/JohnMcLear/esphome_espnow_auth
      ref: main
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
# inside.yaml — same but role: inside
espnow_auth:
  role: inside
  shared_key: !secret espnow_key
```

## Configuration

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `role` | yes | — | `outside` (untrusted, initiates auth) or `inside` (trusted, verifies auth) |
| `shared_key` | yes | — | Pre-shared secret for HMAC-SHA256. Must match on both nodes. |
| `channel` | no | `1` | WiFi channel (1-14) for ESP-NOW. Only used in standalone mode (no `wifi:` block). |

## WiFi coexistence (automatic)

When a `wifi:` block is present in your config, the component automatically layers ESP-NOW on top of ESPHome's WiFi stack. This gives you:

- **OTA updates** over the network (no USB needed after first flash)
- **Home Assistant API** (`api:`)
- **Web server** (`web_server:`)

ESP-NOW automatically follows the AP's channel — both nodes just need to be on the same network.

**Important:** pin your AP to a fixed channel for reliable ESP-NOW operation. If the AP switches channels, connected nodes will follow, but any standalone nodes won't.

## Standalone mode

If you don't need WiFi, simply omit the `wifi:` block. The component detects this and manages the radio directly. All nodes must use the same `channel` value. OTA updates require USB.

## Flashing

First flash over USB:

```bash
esphome run outside.yaml --device /dev/ttyUSB0
esphome run inside.yaml  --device /dev/ttyUSB1
```

After that, with a `wifi:` block present, flash over the network:

```bash
esphome run outside.yaml  # auto-discovers outside-node.local
esphome run inside.yaml   # auto-discovers inside-node.local
```

## Security notes

- The `shared_key` is compiled into the firmware binary as a plain string. Use `!secret` references and keep `secrets.yaml` out of version control. For stronger protection, enable [ESP32 flash encryption](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/flash-encryption.html).
- HMAC verification uses constant-time comparison to prevent timing attacks.
- Each challenge uses a fresh hardware-RNG nonce and must be answered within 10 s, so a recorded handshake response cannot be replayed.
- ESP-NOW frames are unencrypted at the radio level. This component authenticates peers, it does not encrypt payload data.
- Only the handshake is authenticated. Once a peer is authorised, later messages from it are accepted on its MAC address alone, and a MAC address can be spoofed. Do not use the authorised state on its own to gate anything security-relevant, such as an unlock; authenticate that message too.

## License

MIT
