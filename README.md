# Wrmhole

ESP32-based WiFi deauthentication tool with a web interface for authorized security testing.

## Features

- **Deauth Attack** — sends 802.11 deauthentication frames (broadcast or per-client)
- **Client Discovery** — scans for connected clients via promiscuous mode (probe requests + data frames)
- **Whitelist** — exclude your own devices from broadcast attacks
- **Vendor Lookup** — identifies device manufacturers by MAC OUI
- **Continuous Mode** — configurable interval between attack cycles
- **Web Interface** — full control from any browser over WiFi

## Hardware

- ESP32 (ESP-WROOM-32) dev board
- USB cable for flashing
- Connects to your WiFi network as a station (STA mode)

## Requirements

- [ESP-IDF v5.5.0](https://docs.espressif.com/projects/esp-idf/en/v5.5.0/esp32/get-started/)
- ESP32 connected via USB (`/dev/ttyUSB0`)

## Build & Flash

```bash
# Activate ESP-IDF environment
source ~/esp/esp-idf/export.sh

# Build
idf.py build

# Flash (adjust port if needed)
idf.py -p /dev/ttyUSB0 flash
```

## Usage

1. Flash the firmware — ESP32 connects to your WiFi automatically
2. Find the ESP32 IP from serial monitor or your router's DHCP list
3. Open `http://<ESP32_IP>` in a browser
4. Click **Scan** to discover networks and clients
5. Select target and click **START**

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/status` | Device status (WiFi, mode, packet count) |
| `GET /api/scan` | Scan networks and clients (~15s) |
| `GET /api/deauth?reason=4&burst=10&interval=0` | Start broadcast deauth |
| `GET /api/deauth?reason=4&burst=10&client=AA:BB:CC:DD:EE:FF` | Target specific client |
| `GET /api/stop` | Stop attack |
| `GET /api/whitelist` | List whitelisted MACs |
| `GET /api/whitelist/add?mac=AA:BB:CC:DD:EE:FF` | Add MAC to whitelist |
| `GET /api/whitelist/remove?mac=AA:BB:CC:DD:EE:FF` | Remove MAC from whitelist |

### Parameters

| Param | Description | Default |
|-------|-------------|---------|
| `reason` | 802.11 deauth reason code (1, 3, 4, 7) | 4 |
| `burst` | Packets per cycle | 10 |
| `interval` | ms between cycles (0 = continuous) | 0 |
| `client` | Target MAC (omit for broadcast) | — |

### Reason Codes

| Code | Meaning |
|------|---------|
| 1 | Unspecified |
| 3 | Deauth (station leaving) |
| 4 | Inactivity |
| 7 | Class 3 frame from non-associated station |

## How It Works

The ESP32 connects to your WiFi as a regular client. When attack is started, it sends raw 802.11 deauthentication frames using `esp_wifi_80211_tx()`. A link-time override of `ieee80211_raw_frame_sanity_check()` bypasses the ESP-IDF v5.5 filter that normally blocks deauth frames.

Client discovery uses promiscuous mode to capture probe requests and data frames from the target AP's BSSID across all WiFi channels.

## Limitations

- Deauth only works on the connected AP's channel
- Switching channels requires disconnecting from WiFi (kills the web interface)
- Client discovery is passive — requires clients to be actively transmitting

## Disclaimer

**Use only on networks you own or have authorization to test.** Unauthorized deauthentication is illegal in most jurisdictions.

## License

MIT
