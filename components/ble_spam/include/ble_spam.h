#pragma once

typedef enum {
    BLE_SPAM_APPLE,
    BLE_SPAM_SAMSUNG,
    BLE_SPAM_GOOGLE,
    BLE_SPAM_ALL
} ble_spam_type_t;

void ble_spam_start(ble_spam_type_t type);
void ble_spam_stop(void);
