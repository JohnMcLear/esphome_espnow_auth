#pragma once

#include <cstdint>
#include <cstring>
#include <string>

#include <esp_event.h>
#include <esp_mac.h>
#include <esp_netif.h>
#include <esp_now.h>
#include <esp_random.h>
#include <esp_wifi.h>
#include <mbedtls/md.h>
#include <nvs_flash.h>

#include "esphome/core/log.h"

namespace espnow_auth {

static const char *const TAG = "espnow_auth";

// ── Protocol constants ───────────────────────────────────────────────────────

static constexpr uint32_t PING_INTERVAL_MS = 3000;
static constexpr uint32_t AUTH_CHALLENGE_TIMEOUT_MS = 10000;
static constexpr uint32_t AUTH_RETRY_MS = 5000;
static constexpr size_t AUTH_NONCE_LEN = 16;
static constexpr size_t AUTH_HMAC_LEN = 32;  // SHA-256
static constexpr int MAX_AUTH_PEERS = 4;

// ── Message types ────────────────────────────────────────────────────────────

enum MessageType : uint8_t {
    MSG_PING = 0x01,
    MSG_PONG = 0x02,
    MSG_AUTH_REQUEST = 0x10,
    MSG_AUTH_CHALLENGE = 0x11,
    MSG_AUTH_RESPONSE = 0x12,
    MSG_AUTH_OK = 0x13,
    MSG_AUTH_FAIL = 0x14,
};

// ── Wire structures ──────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct EspNowMessage {
    uint8_t type;
    uint32_t counter;
    char text[32];
    uint8_t payload[48];
};

struct AuthChallenge {
    uint8_t nonce[AUTH_NONCE_LEN];
};

struct AuthResponse {
    uint8_t nonce[AUTH_NONCE_LEN];
    uint8_t hmac[AUTH_HMAC_LEN];
};
#pragma pack(pop)

static const uint8_t BROADCAST_ADDR[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ── Peer tracking ────────────────────────────────────────────────────────────

struct AuthPeer {
    bool active;
    bool authorized;
    uint8_t mac[6];
    uint8_t nonce[AUTH_NONCE_LEN];
    uint32_t challenge_sent_ms;
};

// ── Helper functions ─────────────────────────────────────────────────────────

inline void format_mac(const uint8_t *mac, char *buf) {
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

inline void get_mac_str(char *buf) {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    format_mac(mac, buf);
}

/// Compute HMAC-SHA256(nonce, key).
inline bool auth_hmac(const uint8_t *nonce, size_t nonce_len, const char *key, size_t key_len, uint8_t *out) {
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return false;
    return mbedtls_md_hmac(info, (const uint8_t *) key, key_len, nonce, nonce_len, out) == 0;
}

/// Constant-time HMAC comparison.
inline bool auth_hmac_verify(const uint8_t *a, const uint8_t *b) {
    uint8_t diff = 0;
    for (size_t i = 0; i < AUTH_HMAC_LEN; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/// Find an existing peer by MAC, or return the first free slot.
inline AuthPeer *auth_find_peer(AuthPeer *peers, const uint8_t *mac) {
    AuthPeer *free_slot = nullptr;
    for (int i = 0; i < MAX_AUTH_PEERS; i++) {
        if (peers[i].active && memcmp(peers[i].mac, mac, 6) == 0) return &peers[i];
        if (!peers[i].active && !free_slot) free_slot = &peers[i];
    }
    return free_slot;
}

/// Check whether a MAC is in the authorized peer table.
inline bool auth_is_authorized(AuthPeer *peers, const uint8_t *mac) {
    for (int i = 0; i < MAX_AUTH_PEERS; i++) {
        if (peers[i].active && peers[i].authorized && memcmp(peers[i].mac, mac, 6) == 0) return true;
    }
    return false;
}

/// Fill a buffer with hardware-RNG bytes.
inline void generate_nonce(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t r = esp_random();
        size_t chunk = (len - i < 4) ? len - i : 4;
        memcpy(buf + i, &r, chunk);
    }
}

/// Bring up WiFi STA + ESP-NOW.
///
/// @param channel     WiFi channel for ESP-NOW (1-14).
/// @param wifi_coexist  When true, ESPHome's wifi: component owns the radio.
///                      We skip WiFi init and only start ESP-NOW on top of it.
///                      The broadcast peer uses channel 0 (= "current channel")
///                      so it follows wherever the AP puts the station.
inline void espnow_init(uint8_t channel, bool wifi_coexist) {
    esp_err_t ret;

    if (wifi_coexist) {
        // ESPHome's WiFi component has already started the radio.
        // Just pin the channel for ESP-NOW and initialise the protocol.
        ESP_LOGI(TAG, "WiFi coexistence mode — using ESPHome WiFi stack");
    } else {
        // Standalone mode — bring up WiFi ourselves.
        ret = nvs_flash_init();
        if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            nvs_flash_erase();
            ret = nvs_flash_init();
        }
        ESP_LOGI(TAG, "NVS init: %s", esp_err_to_name(ret));

        ret = esp_netif_init();
        ESP_LOGI(TAG, "Netif init: %s", esp_err_to_name(ret));

        ret = esp_event_loop_create_default();
        ESP_LOGI(TAG, "Event loop: %s", esp_err_to_name(ret));

        esp_netif_create_default_wifi_sta();

        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ret = esp_wifi_init(&cfg);
        ESP_LOGI(TAG, "WiFi init: %s", esp_err_to_name(ret));

        esp_wifi_set_storage(WIFI_STORAGE_RAM);
        esp_wifi_set_mode(WIFI_MODE_STA);
        ret = esp_wifi_start();
        ESP_LOGI(TAG, "WiFi start: %s", esp_err_to_name(ret));

        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    }

    if (esp_now_init() != ESP_OK) {
        ESP_LOGE(TAG, "ESP-NOW init failed!");
        return;
    }

    // In coexist mode use channel 0 = "match the station's current channel"
    // so ESP-NOW follows the AP. In standalone mode pin to the requested channel.
    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, BROADCAST_ADDR, 6);
    peer.channel = wifi_coexist ? 0 : channel;
    peer.encrypt = false;
    if (esp_now_add_peer(&peer) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add broadcast peer!");
    }
}

}  // namespace espnow_auth
