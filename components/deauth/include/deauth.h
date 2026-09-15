#pragma once

#include <stdint.h>
#include <stdbool.h>

void deauth_start(uint16_t reason, uint8_t burst, uint16_t interval_ms,
                  const uint8_t *client_mac, bool broadcast);
void deauth_stop(void);
