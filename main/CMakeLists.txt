idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES app_state config scan deauth ble_spam web_server
)
