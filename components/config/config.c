#include "app_state.h"
#include "config.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "nvs_flash.h"
#include <string.h>

static const char *TAG = "config";

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define MAX_RETRY 10

static EventGroupHandle_t s_wifi_event_group;
static int s_retry_num = 0;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        wifi_event_sta_connected_t *event = (wifi_event_sta_connected_t *)event_data;
        memcpy(s_target_bssid, event->bssid, 6);
        s_target_channel = event->channel;
        ESP_LOGI(TAG, "Connected, ch:%d", s_target_channel);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < MAX_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        s_wifi_connected = true;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void nvs_load_wifi_config(void)
{
    nvs_handle_t h;
    if (nvs_open("deauth", NVS_READONLY, &h) == ESP_OK) {
        size_t len = sizeof(s_wifi_ssid);
        if (nvs_get_str(h, "ssid", s_wifi_ssid, &len) != ESP_OK) {
            strncpy(s_wifi_ssid, DEFAULT_WIFI_SSID, sizeof(s_wifi_ssid));
        }
        len = sizeof(s_wifi_pass);
        if (nvs_get_str(h, "pass", s_wifi_pass, &len) != ESP_OK) {
            strncpy(s_wifi_pass, DEFAULT_WIFI_PASS, sizeof(s_wifi_pass));
        }
        nvs_close(h);
        ESP_LOGI(TAG, "Loaded from NVS: %s", s_wifi_ssid);
    } else {
        strncpy(s_wifi_ssid, DEFAULT_WIFI_SSID, sizeof(s_wifi_ssid));
        strncpy(s_wifi_pass, DEFAULT_WIFI_PASS, sizeof(s_wifi_pass));
        ESP_LOGI(TAG, "NVS empty, using defaults");
    }
}

void nvs_save_wifi_config(const char *ssid, const char *pass)
{
    nvs_handle_t h;
    if (nvs_open("deauth", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "ssid", ssid);
        nvs_set_str(h, "pass", pass);
        nvs_commit(h);
        nvs_close(h);
        strncpy(s_wifi_ssid, ssid, sizeof(s_wifi_ssid));
        strncpy(s_wifi_pass, pass, sizeof(s_wifi_pass));
        ESP_LOGI(TAG, "Saved: %s", ssid);
    }
}

void nvs_clear_wifi_config(void)
{
    nvs_handle_t h;
    if (nvs_open("deauth", NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h);
        nvs_commit(h);
        nvs_close(h);
    }
    strncpy(s_wifi_ssid, DEFAULT_WIFI_SSID, sizeof(s_wifi_ssid));
    strncpy(s_wifi_pass, DEFAULT_WIFI_PASS, sizeof(s_wifi_pass));
    ESP_LOGI(TAG, "Cleared, using defaults");
}

void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                    &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                    &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, s_wifi_ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, s_wifi_pass, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to %s...", s_wifi_ssid);
    esp_wifi_connect();

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE, pdFALSE, portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to %s", s_wifi_ssid);
        s_ap_mode = false;
        /* Get BSSID/channel from AP info if not set by event */
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            memcpy(s_target_bssid, ap_info.bssid, 6);
            s_target_channel = ap_info.primary;
            strncpy(s_target_ssid, (char *)ap_info.ssid, 32);
            s_target_ssid[32] = '\0';
        }
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "Failed to connect. Starting AP...");
        s_ap_mode = true;
        esp_wifi_stop();
        wifi_init_ap();
    }
}

void wifi_init_ap(void)
{
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t ap_config = {
        .ap = {
            .ssid = AP_SSID,
            .ssid_len = strlen(AP_SSID),
            .channel = 1,
            .password = AP_PASS,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "AP: %s", AP_SSID);
}
