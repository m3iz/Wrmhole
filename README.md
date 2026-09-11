# ESP32 Deauth Tool

Прошивка для ESP32, которая отправляет deauthentication пакеты в собственной Wi-Fi сети для тестирования безопасности.

## Возможности

- **Deauth атака** — отправка deauthentication пакетов
- **Сканирование** — поиск сетей и клиентов
- **Web интерфейс** — управление через браузер
- **Белый список** — автоматическое исключение своего устройства

## Требования

- ESP32 (ESP-WROOM-32, ESP32-S2, ESP32-S3)
- PlatformIO
- USB кабель для прошивки

## Установка

```bash
cd /home/nsaveliev/Documents/personal/test
pio run -t upload
```

## Использование

1. Прошейте ESP32
2. Подключитесь к WiFi "ESP32-Deauth" (пароль: 12345678)
3. Откройте http://192.168.4.1
4. Нажмите "Сканировать" для поиска сетей
5. Выберите цель и нажмите "Начать атаку"

## API

- `GET /api/status` — статус устройства
- `GET /api/scan` — сканирование сетей
- `GET /api/deauth?reason=4&burst=5` — deauth broadcast
- `GET /api/deauth?reason=4&burst=5&client=AA:BB:CC:DD:EE:FF` — deauth клиента
- `GET /api/stop` — остановка атаки

## Коды причин (Reason Codes)

| Код | Описание |
|-----|----------|
| 1 | Unspecified |
| 3 | Deauth (станция уходит) |
| 4 | Inactivity |
| 7 | Class 3 frame from non-associated |

## Важно

**Используйте только для тестирования собственных сетей!**
Несанкционированная деаутентификацияillegal в большинстве юрисдикций.
