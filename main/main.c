/**
 * Wrmhole — ESP32 Deauth Tool
 * ESP-IDF v5.5 — Component-based architecture
 */

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "app_state.h"
#include "config.h"
#include "scan.h"
#include "deauth.h"
#include "ble_spam.h"
#include "web_server.h"

static const char *TAG = "main";

/*
 * Link-time override: bypass the WiFi blob's sanity check that
 * rejects deauth / disassoc management frames in esp_wifi_80211_tx().
 */
int ieee80211_raw_frame_sanity_check(int arg) { return 0; }

/* =====================================================
 *  Auto-scan on boot
 * ===================================================== */

static void boot_scan_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(5000));
    ESP_LOGI(TAG, "Auto-scan on boot...");
    scan_run();
    ESP_LOGI(TAG, "Auto-scan done: %d networks, %d clients", s_network_count, s_client_count);
    vTaskDelete(NULL);
}

/* =====================================================
 *  Main
 * ===================================================== */

void app_main(void)
{
    ESP_LOGI(TAG, "=== Wrmhole ===");

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    s_scan_mutex = xSemaphoreCreateMutex();

    nvs_load_wifi_config();
    wifi_init_sta();
    web_server_start();

    /* Auto-scan on boot */
    xTaskCreate(boot_scan_task, "boot_scan", 4096, NULL, 3, NULL);

    ESP_LOGI(TAG, "Ready! Open http://<ESP_IP> in browser");
}
