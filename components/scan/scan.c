#include "app_state.h"
#include "scan.h"

#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>

static const char *TAG = "scan";

#define SCAN_CHANNEL_DWELL_MS 500

static bool mac_is_multicast(const uint8_t *mac)
{
    return mac[0] & 0x01;
}

static bool mac_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

static void IRAM_ATTR promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type == WIFI_PKT_MGMT) {
        const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
        const uint8_t *frame = pkt->payload;
        int len = pkt->rx_ctrl.sig_len;
        if (len < 24) return;

        uint8_t frame_subtype = (frame[0] >> 4) & 0x0F;

        /* Beacon */
        if (frame_subtype == 8) {
            if (len < 36) return;
            uint8_t *bssid = (uint8_t *)(frame + 10);
            int pos = 24;
            while (pos + 1 < len) {
                uint8_t ie_id = frame[pos];
                uint8_t ie_len = frame[pos + 1];
                if (ie_id == 0 && ie_len > 0 && ie_len < 33 && pos + 2 + ie_len <= len) {
                    char ssid[34] = {0};
                    memcpy(ssid, frame + pos + 2, ie_len);
                    bool found = false;
                    for (int i = 0; i < s_network_count; i++) {
                        if (mac_eq(s_networks[i].bssid, bssid)) { found = true; break; }
                    }
                    if (!found && s_network_count < MAX_NETWORKS) {
                        memcpy(s_networks[s_network_count].bssid, bssid, 6);
                        s_networks[s_network_count].rssi = pkt->rx_ctrl.rssi;
                        s_networks[s_network_count].channel = pkt->rx_ctrl.channel;
                        strncpy(s_networks[s_network_count].ssid, ssid, 32);
                        s_network_count++;
                    }
                    break;
                }
                pos += 2 + ie_len;
            }
        }

        /* Probe Request */
        if (frame_subtype == 4) {
            uint8_t *src = (uint8_t *)(frame + 10);
            if (mac_is_multicast(src)) return;
            bool found = false;
            for (int i = 0; i < s_client_count; i++) {
                if (mac_eq(s_clients[i].mac, src)) {
                    s_clients[i].rssi = pkt->rx_ctrl.rssi;
                    found = true;
                    break;
                }
            }
            if (!found && s_client_count < MAX_CLIENTS) {
                memcpy(s_clients[s_client_count].mac, src, 6);
                s_clients[s_client_count].rssi = pkt->rx_ctrl.rssi;
                s_clients[s_client_count].channel = pkt->rx_ctrl.channel;
                s_client_count++;
            }
        }
    }

    if (type == WIFI_PKT_DATA) {
        const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
        const uint8_t *frame = pkt->payload;
        int len = pkt->rx_ctrl.sig_len;
        if (len < 24) return;

        uint8_t *addr1 = (uint8_t *)(frame + 4);
        uint8_t *addr2 = (uint8_t *)(frame + 10);
        uint8_t *addr3 = (uint8_t *)(frame + 16);

        bool addr3_is_ap = false;
        for (int i = 0; i < s_network_count; i++) {
            if (mac_eq(addr3, s_networks[i].bssid)) { addr3_is_ap = true; break; }
        }

        uint8_t *client_mac = NULL;
        if (addr3_is_ap) {
            if (!mac_is_multicast(addr1)) client_mac = addr1;
            else if (!mac_is_multicast(addr2)) client_mac = addr2;
        }

        if (client_mac) {
            bool found = false;
            for (int i = 0; i < s_client_count; i++) {
                if (mac_eq(s_clients[i].mac, client_mac)) {
                    s_clients[i].rssi = pkt->rx_ctrl.rssi;
                    found = true;
                    break;
                }
            }
            if (!found && s_client_count < MAX_CLIENTS) {
                memcpy(s_clients[s_client_count].mac, client_mac, 6);
                s_clients[s_client_count].rssi = pkt->rx_ctrl.rssi;
                s_clients[s_client_count].channel = pkt->rx_ctrl.channel;
                s_client_count++;
            }
        }
    }
}

esp_err_t scan_run(void)
{
    if (xSemaphoreTake(s_scan_mutex, 0) != pdTRUE) {
        ESP_LOGW(TAG, "Scan already in progress");
        return ESP_ERR_TIMEOUT;
    }

    /* WiFi scan for networks (incremental) */
    wifi_scan_config_t scan_cfg = {0};
    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WiFi scan failed: %s", esp_err_to_name(err));
        xSemaphoreGive(s_scan_mutex);
        return err;
    }

    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_num(&ap_count);
    if (ap_count > MAX_NETWORKS) ap_count = MAX_NETWORKS;

    wifi_ap_record_t *ap_records = calloc(ap_count, sizeof(wifi_ap_record_t));
    if (ap_records) {
        esp_wifi_scan_get_ap_records(&ap_count, ap_records);
        for (int i = 0; i < ap_count; i++) {
            bool found = false;
            for (int j = 0; j < s_network_count; j++) {
                if (mac_eq(s_networks[j].bssid, ap_records[i].bssid)) {
                    s_networks[j].rssi = ap_records[i].rssi;
                    found = true;
                    break;
                }
            }
            if (!found && s_network_count < MAX_NETWORKS) {
                memcpy(s_networks[s_network_count].bssid, ap_records[i].bssid, 6);
                s_networks[s_network_count].rssi = ap_records[i].rssi;
                s_networks[s_network_count].channel = ap_records[i].primary;
                strncpy(s_networks[s_network_count].ssid, (char *)ap_records[i].ssid, 32);
                s_networks[s_network_count].ssid[32] = '\0';
                s_network_count++;
            }
        }
        free(ap_records);
    }

    /* Promiscuous scan for clients */
    s_client_count = 0;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuous_cb);
    if (s_wifi_connected) {
        /* STA mode: can't switch channels, listen on current channel only */
        vTaskDelay(pdMS_TO_TICKS(3000));
    } else {
        for (int ch = 1; ch <= 13; ch++) {
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            vTaskDelay(pdMS_TO_TICKS(SCAN_CHANNEL_DWELL_MS));
        }
    }
    esp_wifi_set_promiscuous(false);

    xSemaphoreGive(s_scan_mutex);
    ESP_LOGI(TAG, "Scan done: %d networks, %d clients", s_network_count, s_client_count);
    return ESP_OK;
}
