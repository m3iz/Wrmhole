#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define MAX_NETWORKS  30
#define MAX_CLIENTS   30
#define MAX_WHITELIST 10

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

/* Globals */
extern network_info_t s_networks[MAX_NETWORKS];
extern client_info_t  s_clients[MAX_CLIENTS];
extern int s_network_count;
extern int s_client_count;

extern uint8_t s_whitelist[MAX_WHITELIST][6];
extern int s_whitelist_count;

extern uint8_t s_target_bssid[6];
extern uint8_t s_target_channel;
extern char    s_target_ssid[33];

extern uint8_t  s_target_client[6];
extern volatile bool s_target_client_valid;

extern volatile bool s_deauth_running;
extern volatile bool s_deauth_broadcast;
extern volatile uint32_t s_deauth_count;
extern volatile uint16_t s_deauth_reason;
extern volatile uint8_t  s_deauth_burst;
extern volatile uint16_t s_deauth_interval_ms;

extern volatile bool s_ble_spam_running;
extern volatile uint32_t s_ble_spam_count;

extern char s_wifi_ssid[33];
extern char s_wifi_pass[65];
extern volatile bool s_wifi_connected;
extern volatile bool s_ap_mode;

extern SemaphoreHandle_t s_scan_mutex;

/* Utility */
const char *lookup_vendor(const uint8_t *mac);
bool is_whitelisted(const uint8_t *mac);
