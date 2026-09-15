#pragma once

#include "esp_err.h"

#define DEFAULT_WIFI_SSID  "WIFI-2"
#define DEFAULT_WIFI_PASS  "1234567898765"
#define AP_SSID            "ESP32-Deauth"
#define AP_PASS            "12345678"

void nvs_load_wifi_config(void);
void nvs_save_wifi_config(const char *ssid, const char *pass);
void nvs_clear_wifi_config(void);
void wifi_init_sta(void);
void wifi_init_ap(void);
