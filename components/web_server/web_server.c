#include "web_server.h"
#include "index_html.h"
#include "app_state.h"
#include "scan.h"
#include "deauth.h"
#include "ble_spam.h"
#include "config.h"

#include <string.h>
#include <stdio.h>
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"

static const char *TAG = "web_server";
static httpd_handle_t s_server = NULL;

/* =====================================================
 *  Handlers
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

    /* Build JSON manually for speed */
    char buf[3072];
    int off = snprintf(buf, sizeof(buf),
        "{\"wifi\":%s,\"ssid\":\"%s\",\"target_bssid\":\"%s\","
        "\"target_channel\":%d,\"ip\":\"%s\",\"mode\":\"%s\","
        "\"deauth_count\":%lu,\"client_count\":%d,\"network_count\":%d,"
        "\"ble_spam\":%s,\"ble_spam_count\":%lu,\"clients_detail\":[",
        s_wifi_connected ? "true" : "false",
        s_target_ssid,
        target_bssid,
        s_target_channel,
        ip_str,
        s_deauth_running ? "DEAUTH" : (s_ble_spam_running ? "BLE_SPAM" : "IDLE"),
        (unsigned long)s_deauth_count,
        s_client_count,
        s_network_count,
        s_ble_spam_running ? "true" : "false",
        (unsigned long)s_ble_spam_count);

    for (int i = 0; i < s_client_count && i < 30 && off < (int)sizeof(buf) - 200; i++) {
        if (i > 0) buf[off++] = ',';
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 s_clients[i].mac[0], s_clients[i].mac[1], s_clients[i].mac[2],
                 s_clients[i].mac[3], s_clients[i].mac[4], s_clients[i].mac[5]);
        off += snprintf(buf + off, sizeof(buf) - off,
            "{\"mac\":\"%s\",\"vendor\":\"%s\",\"rssi\":%d,\"channel\":%d,\"whitelisted\":%s}",
            mac, lookup_vendor(s_clients[i].mac),
            s_clients[i].rssi, s_clients[i].channel,
            is_whitelisted(s_clients[i].mac) ? "true" : "false");
    }
    off += snprintf(buf + off, sizeof(buf) - off, "]}");

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, off);
}

static esp_err_t handle_scan(httpd_req_t *req)
{
    esp_err_t err = scan_run();
    if (err != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char buf[4096];
    int off = snprintf(buf, sizeof(buf), "{\"networks\":[");
    for (int i = 0; i < s_network_count && off < (int)sizeof(buf) - 200; i++) {
        if (i > 0) buf[off++] = ',';
        char bssid[18];
        snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
                 s_networks[i].bssid[0], s_networks[i].bssid[1], s_networks[i].bssid[2],
                 s_networks[i].bssid[3], s_networks[i].bssid[4], s_networks[i].bssid[5]);
        off += snprintf(buf + off, sizeof(buf) - off,
            "{\"ssid\":\"%s\",\"bssid\":\"%s\",\"channel\":%d,\"rssi\":%d}",
            s_networks[i].ssid, bssid, s_networks[i].channel, s_networks[i].rssi);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "],\"clients\":[");
    for (int i = 0; i < s_client_count && off < (int)sizeof(buf) - 200; i++) {
        if (i > 0) buf[off++] = ',';
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 s_clients[i].mac[0], s_clients[i].mac[1], s_clients[i].mac[2],
                 s_clients[i].mac[3], s_clients[i].mac[4], s_clients[i].mac[5]);
        off += snprintf(buf + off, sizeof(buf) - off,
            "{\"mac\":\"%s\",\"vendor\":\"%s\",\"rssi\":%d,\"channel\":%d,\"whitelisted\":%s}",
            mac, lookup_vendor(s_clients[i].mac),
            s_clients[i].rssi, s_clients[i].channel,
            is_whitelisted(s_clients[i].mac) ? "true" : "false");
    }
    off += snprintf(buf + off, sizeof(buf) - off, "]}");

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, off);
}

static esp_err_t handle_deauth(httpd_req_t *req)
{
    char query[128] = {0};
    esp_err_t err = httpd_req_get_url_query_str(req, query, sizeof(query));
    if (err != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char enable_str[8] = {0};
    httpd_query_key_value(query, "enable", enable_str, sizeof(enable_str));

    if (strlen(enable_str) > 0 && atoi(enable_str) == 0) {
        deauth_stop();
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_send(req, "{\"status\":\"Stopped\"}", -1);
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
    if (reason > 66) reason = 4;
    if (burst < 1) burst = 1;
    if (burst > 100) burst = 100;

    uint8_t client_mac[6];
    bool broadcast = true;
    if (strlen(client_str) > 0) {
        if (sscanf(client_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &client_mac[0], &client_mac[1], &client_mac[2],
                   &client_mac[3], &client_mac[4], &client_mac[5]) != 6) {
            httpd_resp_send_500(req);
            return ESP_FAIL;
        }
        broadcast = false;
    }

    deauth_start(reason, burst, interval, broadcast ? NULL : client_mac, broadcast);

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"status\":\"Attack started\"}", -1);
}

static esp_err_t handle_stop(httpd_req_t *req)
{
    deauth_stop();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"status\":\"Stopped\"}", -1);
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

    /* Duplicate check */
    for (int i = 0; i < s_whitelist_count; i++) {
        if (memcmp(s_whitelist[i], mac, 6) == 0) {
            httpd_resp_set_type(req, "application/json");
            char resp[64];
            snprintf(resp, sizeof(resp), "{\"status\":\"Already in whitelist\",\"count\":%d}", s_whitelist_count);
            return httpd_resp_send(req, resp, -1);
        }
    }

    memcpy(s_whitelist[s_whitelist_count], mac, 6);
    s_whitelist_count++;

    char resp[64];
    snprintf(resp, sizeof(resp), "{\"status\":\"Added\",\"count\":%d}", s_whitelist_count);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, -1);
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

    char resp[64];
    snprintf(resp, sizeof(resp), "{\"status\":\"Removed\",\"count\":%d}", s_whitelist_count);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, -1);
}

static esp_err_t handle_wl_list(httpd_req_t *req)
{
    char buf[1024];
    int off = snprintf(buf, sizeof(buf), "{\"whitelist\":[");
    for (int i = 0; i < s_whitelist_count; i++) {
        if (i > 0) buf[off++] = ',';
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 s_whitelist[i][0], s_whitelist[i][1], s_whitelist[i][2],
                 s_whitelist[i][3], s_whitelist[i][4], s_whitelist[i][5]);
        off += snprintf(buf + off, sizeof(buf) - off, "\"%s\"", mac);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "],\"count\":%d}", s_whitelist_count);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, off);
}

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

    ble_spam_start(type);

    char resp[64];
    snprintf(resp, sizeof(resp), "{\"status\":\"BLE Spam started\",\"type\":\"%s\"}", type_str);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, -1);
}

static esp_err_t handle_ble_spam_stop(httpd_req_t *req)
{
    ble_spam_stop();
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"status\":\"BLE Spam stopped\",\"count\":%lu}", (unsigned long)s_ble_spam_count);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, -1);
}

static esp_err_t handle_wifi_config_get(httpd_req_t *req)
{
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"ssid\":\"%s\",\"connected\":%s,\"ap_mode\":%s}",
             s_wifi_ssid, s_wifi_connected ? "true" : "false", s_ap_mode ? "true" : "false");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, -1);
}

static esp_err_t handle_wifi_config_set(httpd_req_t *req)
{
    char query[128] = {0};
    httpd_req_get_url_query_str(req, query, sizeof(query));
    char ssid[33] = {0};
    char pass[65] = {0};
    httpd_query_key_value(query, "ssid", ssid, sizeof(ssid));
    httpd_query_key_value(query, "pass", pass, sizeof(pass));

    if (strlen(ssid) == 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    nvs_save_wifi_config(ssid, pass);

    char resp[96];
    snprintf(resp, sizeof(resp), "{\"status\":\"Saved. Reboot to apply.\",\"ssid\":\"%s\"}", ssid);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, -1);
}

static esp_err_t handle_wifi_config_reset(httpd_req_t *req)
{
    nvs_clear_wifi_config();
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"status\":\"Reset to defaults. Reboot to apply.\"}", -1);
}

static esp_err_t handle_reboot(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"Rebooting...\"}", -1);
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

/* =====================================================
 *  Server start
 * ===================================================== */

void web_server_start(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_uri_handlers = 16;
    config.stack_size = 8192;

    if (httpd_start(&s_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start web server");
        return;
    }

    const httpd_uri_t uris[] = {
        { .uri = "/",                    .method = HTTP_GET, .handler = handle_index },
        { .uri = "/api/status",          .method = HTTP_GET, .handler = handle_status },
        { .uri = "/api/scan",            .method = HTTP_GET, .handler = handle_scan },
        { .uri = "/api/deauth",          .method = HTTP_GET, .handler = handle_deauth },
        { .uri = "/api/stop",            .method = HTTP_GET, .handler = handle_stop },
        { .uri = "/api/whitelist/add",   .method = HTTP_GET, .handler = handle_wl_add },
        { .uri = "/api/whitelist/remove",.method = HTTP_GET, .handler = handle_wl_rm },
        { .uri = "/api/whitelist",       .method = HTTP_GET, .handler = handle_wl_list },
        { .uri = "/api/ble/spam/start",  .method = HTTP_GET, .handler = handle_ble_spam_start },
        { .uri = "/api/ble/spam/stop",   .method = HTTP_GET, .handler = handle_ble_spam_stop },
        { .uri = "/api/wifi/config",     .method = HTTP_GET, .handler = handle_wifi_config_get },
        { .uri = "/api/wifi/set",        .method = HTTP_GET, .handler = handle_wifi_config_set },
        { .uri = "/api/wifi/reset",      .method = HTTP_GET, .handler = handle_wifi_config_reset },
        { .uri = "/api/reboot",          .method = HTTP_GET, .handler = handle_reboot },
    };

    for (int i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        httpd_uri_t uri = uris[i];
        uri.user_ctx = NULL;
        httpd_register_uri_handler(s_server, &uri);
    }

    ESP_LOGI(TAG, "Web server started on port 80");
}
