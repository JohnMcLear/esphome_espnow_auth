#pragma once

#include "espnow_base.h"
#include "esphome/core/component.h"

namespace espnow_auth {

class ESPNowInside : public esphome::Component {
 public:
    void set_shared_key(const std::string &key) { shared_key_ = key; }
    void set_channel(uint8_t ch) { channel_ = ch; }
    void set_wifi_coexist(bool v) { wifi_coexist_ = v; }
    float get_setup_priority() const override { return esphome::setup_priority::LATE; }

    void setup() override {
        instance_ = this;
        memset(auth_peers_, 0, sizeof(auth_peers_));
        ESP_LOGI(TAG, "=== INSIDE (trusted) node ===");

        espnow_init(channel_, wifi_coexist_);
        esp_now_register_send_cb(on_sent_cb);
        esp_now_register_recv_cb(on_recv_cb);

        char mac_buf[18];
        get_mac_str(mac_buf);
        ESP_LOGI(TAG, "MAC: %s", mac_buf);
        ESP_LOGI(TAG, "Ready. Waiting for auth requests...");
    }

    void loop() override {
        uint32_t now = millis();
        for (int i = 0; i < MAX_AUTH_PEERS; i++) {
            if (auth_peers_[i].active && !auth_peers_[i].authorized &&
                now - auth_peers_[i].challenge_sent_ms > AUTH_CHALLENGE_TIMEOUT_MS) {
                char mac_str[18];
                format_mac(auth_peers_[i].mac, mac_str);
                ESP_LOGW(TAG, "[IN] Challenge expired for %s, freeing slot", mac_str);
                auth_peers_[i].active = false;
            }
        }
    }

 protected:
    static ESPNowInside *instance_;

    std::string shared_key_;
    uint8_t channel_{1};
    bool wifi_coexist_{false};
    AuthPeer auth_peers_[MAX_AUTH_PEERS];

    void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
        if (len < static_cast<int>(sizeof(EspNowMessage))) return;
        const auto *msg = reinterpret_cast<const EspNowMessage *>(data);
        char mac_str[18];
        format_mac(info->src_addr, mac_str);

        switch (msg->type) {
            case MSG_AUTH_REQUEST: {
                ESP_LOGI(TAG, "[IN] AUTH_REQUEST from %s", mac_str);

                if (auth_is_authorized(auth_peers_, info->src_addr)) {
                    EspNowMessage ok = {};
                    ok.type = MSG_AUTH_OK;
                    snprintf(ok.text, sizeof(ok.text), "already-authed");
                    esp_now_send(BROADCAST_ADDR, (uint8_t *) &ok, sizeof(ok));
                    return;
                }

                AuthPeer *peer = auth_find_peer(auth_peers_, info->src_addr);
                if (!peer) {
                    ESP_LOGW(TAG, "[IN] Auth peer table full, ignoring");
                    return;
                }

                peer->active = true;
                peer->authorized = false;
                memcpy(peer->mac, info->src_addr, 6);
                generate_nonce(peer->nonce, AUTH_NONCE_LEN);
                peer->challenge_sent_ms = millis();

                EspNowMessage reply = {};
                reply.type = MSG_AUTH_CHALLENGE;
                AuthChallenge challenge;
                memcpy(challenge.nonce, peer->nonce, AUTH_NONCE_LEN);
                memcpy(reply.payload, &challenge, sizeof(challenge));
                snprintf(reply.text, sizeof(reply.text), "challenge");

                ESP_LOGI(TAG, "[IN] Sending AUTH_CHALLENGE to %s", mac_str);
                esp_now_send(BROADCAST_ADDR, (uint8_t *) &reply, sizeof(reply));
                break;
            }

            case MSG_AUTH_RESPONSE: {
                ESP_LOGI(TAG, "[IN] AUTH_RESPONSE from %s", mac_str);

                AuthPeer *peer = auth_find_peer(auth_peers_, info->src_addr);
                if (!peer || !peer->active || peer->authorized) {
                    ESP_LOGW(TAG, "[IN] No pending challenge for this peer");
                    return;
                }

                if (millis() - peer->challenge_sent_ms > AUTH_CHALLENGE_TIMEOUT_MS) {
                    ESP_LOGW(TAG, "[IN] Challenge expired, rejecting");
                    peer->active = false;
                    EspNowMessage fail = {};
                    fail.type = MSG_AUTH_FAIL;
                    snprintf(fail.text, sizeof(fail.text), "expired");
                    esp_now_send(BROADCAST_ADDR, (uint8_t *) &fail, sizeof(fail));
                    return;
                }

                AuthResponse resp;
                memcpy(&resp, msg->payload, sizeof(resp));

                if (memcmp(resp.nonce, peer->nonce, AUTH_NONCE_LEN) != 0) {
                    ESP_LOGW(TAG, "[IN] Nonce mismatch, rejecting");
                    peer->active = false;
                    EspNowMessage fail = {};
                    fail.type = MSG_AUTH_FAIL;
                    snprintf(fail.text, sizeof(fail.text), "bad-nonce");
                    esp_now_send(BROADCAST_ADDR, (uint8_t *) &fail, sizeof(fail));
                    return;
                }

                uint8_t expected[AUTH_HMAC_LEN];
                if (!auth_hmac(peer->nonce, AUTH_NONCE_LEN, shared_key_.c_str(), shared_key_.size(), expected)) {
                    ESP_LOGE(TAG, "[IN] HMAC computation failed!");
                    return;
                }

                if (!auth_hmac_verify(resp.hmac, expected)) {
                    ESP_LOGW(TAG, "[IN] HMAC mismatch - REJECTING %s", mac_str);
                    peer->active = false;
                    EspNowMessage fail = {};
                    fail.type = MSG_AUTH_FAIL;
                    snprintf(fail.text, sizeof(fail.text), "bad-hmac");
                    esp_now_send(BROADCAST_ADDR, (uint8_t *) &fail, sizeof(fail));
                    return;
                }

                peer->authorized = true;
                ESP_LOGI(TAG, "[IN] ** %s AUTHORIZED **", mac_str);
                EspNowMessage ok = {};
                ok.type = MSG_AUTH_OK;
                snprintf(ok.text, sizeof(ok.text), "welcome");
                esp_now_send(BROADCAST_ADDR, (uint8_t *) &ok, sizeof(ok));
                break;
            }

            case MSG_PING: {
                if (!auth_is_authorized(auth_peers_, info->src_addr)) {
                    ESP_LOGW(TAG, "[IN] PING from UNAUTHORIZED %s - ignored", mac_str);
                    return;
                }

                ESP_LOGI(TAG, "[IN] Got PING #%u from %s: %s", msg->counter, mac_str, msg->text);

                EspNowMessage reply = {};
                reply.type = MSG_PONG;
                reply.counter = msg->counter;
                snprintf(reply.text, sizeof(reply.text), "pong #%u", msg->counter);
                esp_now_send(BROADCAST_ADDR, (uint8_t *) &reply, sizeof(reply));
                break;
            }

            default:
                break;
        }
    }

    static void on_sent_cb(const esp_now_send_info_t *info, esp_now_send_status_t status) {
        ESP_LOGD(TAG, "[IN] Send %s", status == ESP_NOW_SEND_SUCCESS ? "OK" : "FAIL");
    }

    static void on_recv_cb(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
        if (instance_) instance_->on_recv(info, data, len);
    }
};

ESPNowInside *ESPNowInside::instance_ = nullptr;

}  // namespace espnow_auth
