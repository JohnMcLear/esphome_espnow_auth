#pragma once

#include "espnow_base.h"
#include "esphome/core/component.h"

namespace espnow_auth {

class ESPNowOutside : public esphome::Component {
 public:
    void set_shared_key(const std::string &key) { shared_key_ = key; }
    void set_channel(uint8_t ch) { channel_ = ch; }
    void set_wifi_coexist(bool v) { wifi_coexist_ = v; }
    float get_setup_priority() const override { return esphome::setup_priority::LATE; }

    void setup() override {
        instance_ = this;
        ESP_LOGI(TAG, "=== OUTSIDE (untrusted) node ===");

        espnow_init(channel_, wifi_coexist_);
        esp_now_register_send_cb(on_sent_cb);
        esp_now_register_recv_cb(on_recv_cb);

        char mac_buf[18];
        get_mac_str(mac_buf);
        ESP_LOGI(TAG, "MAC: %s", mac_buf);
        ESP_LOGI(TAG, "Ready. Starting auth handshake...");
        send_auth_request();
    }

    void loop() override {
        uint32_t now = millis();

        if (!authenticated_) {
            if (!auth_pending_ || (now - auth_request_time_ >= AUTH_RETRY_MS)) {
                send_auth_request();
            }
            return;
        }

        if (now - last_ping_ >= PING_INTERVAL_MS) {
            last_ping_ = now;
            ping_counter_++;

            EspNowMessage msg = {};
            msg.type = MSG_PING;
            msg.counter = ping_counter_;
            snprintf(msg.text, sizeof(msg.text), "ping #%u", ping_counter_);

            ESP_LOGI(TAG, "[OUT] Sending PING #%u", ping_counter_);
            esp_now_send(BROADCAST_ADDR, (uint8_t *) &msg, sizeof(msg));
        }
    }

 protected:
    static ESPNowOutside *instance_;

    std::string shared_key_;
    uint8_t channel_{1};
    bool wifi_coexist_{false};
    uint32_t ping_counter_{0};
    uint32_t last_ping_{0};
    bool authenticated_{false};
    bool auth_pending_{false};
    uint32_t auth_request_time_{0};

    void send_auth_request() {
        EspNowMessage msg = {};
        msg.type = MSG_AUTH_REQUEST;
        snprintf(msg.text, sizeof(msg.text), "auth-req");
        ESP_LOGI(TAG, "[OUT] Sending AUTH_REQUEST");
        esp_now_send(BROADCAST_ADDR, (uint8_t *) &msg, sizeof(msg));
        auth_pending_ = true;
        auth_request_time_ = millis();
    }

    void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
        if (len < static_cast<int>(sizeof(EspNowMessage))) return;
        const auto *msg = reinterpret_cast<const EspNowMessage *>(data);
        char mac_str[18];
        format_mac(info->src_addr, mac_str);

        switch (msg->type) {
            case MSG_AUTH_CHALLENGE: {
                ESP_LOGI(TAG, "[OUT] Got AUTH_CHALLENGE from %s", mac_str);
                AuthChallenge challenge;
                memcpy(&challenge, msg->payload, sizeof(challenge));

                AuthResponse resp;
                memcpy(resp.nonce, challenge.nonce, AUTH_NONCE_LEN);
                if (!auth_hmac(challenge.nonce, AUTH_NONCE_LEN, shared_key_.c_str(), shared_key_.size(), resp.hmac)) {
                    ESP_LOGE(TAG, "[OUT] HMAC computation failed!");
                    return;
                }

                EspNowMessage reply = {};
                reply.type = MSG_AUTH_RESPONSE;
                memcpy(reply.payload, &resp, sizeof(resp));
                snprintf(reply.text, sizeof(reply.text), "auth-resp");
                ESP_LOGI(TAG, "[OUT] Sending AUTH_RESPONSE");
                esp_now_send(BROADCAST_ADDR, (uint8_t *) &reply, sizeof(reply));
                break;
            }
            case MSG_AUTH_OK:
                ESP_LOGI(TAG, "[OUT] Authenticated by %s!", mac_str);
                authenticated_ = true;
                auth_pending_ = false;
                break;
            case MSG_AUTH_FAIL:
                ESP_LOGW(TAG, "[OUT] Auth REJECTED by %s", mac_str);
                auth_pending_ = false;
                break;
            case MSG_PONG:
                ESP_LOGI(TAG, "[OUT] Got PONG #%u from %s: %s", msg->counter, mac_str, msg->text);
                break;
            default:
                break;
        }
    }

    static void on_sent_cb(const esp_now_send_info_t *info, esp_now_send_status_t status) {
        ESP_LOGD(TAG, "[OUT] Send %s", status == ESP_NOW_SEND_SUCCESS ? "OK" : "FAIL");
    }

    static void on_recv_cb(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
        if (instance_) instance_->on_recv(info, data, len);
    }
};

ESPNowOutside *ESPNowOutside::instance_ = nullptr;

}  // namespace espnow_auth
