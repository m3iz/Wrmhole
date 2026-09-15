idf_component_register(
    SRCS "web_server.c"
    INCLUDE_DIRS "include"
    REQUIRES app_state scan deauth ble_spam config esp_http_server
)
