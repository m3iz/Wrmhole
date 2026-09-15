idf_component_register(
    SRCS "config.c"
    INCLUDE_DIRS "include"
    REQUIRES app_state nvs_flash esp_wifi esp_event esp_netif
)
