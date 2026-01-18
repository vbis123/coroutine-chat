# TCP Broadcast Chat (Web client + WS<->TCP proxy)

Небольшой Node.js proxy, который соединяет браузерный WebSocket с существующим TCP C++ сервером, использующим framing: `uint32 length (network byte order) + payload`.

## Архитектура
- **WS <-> TCP bridge**: на каждое WS-подключение создается TCP-сокет к `TCP_HOST:TCP_PORT`.
- **Framing и протокол**:
  - из браузера: payload превращается в `4-byte length + payload` и отправляется в TCP;
  - из TCP: поток буферизуется, извлекаются полные фреймы и пересылаются в WS.
  - первый кадр от клиента — никнейм (как ожидает C++ сервер).
- **Личные сообщения**: клиент отправляет JSON (`{type, from, to, body}`); все сообщения все равно идут через TCP broadcast, а фильтрация делается в браузере.
- **Подсказки получателей**: список никнеймов собирается из join/leave и сообщений, доступен в поле `To`.
- **Шифрование личных**: если `To` не `all` и указан `Secret`, тело шифруется AES‑GCM на клиенте (PBKDF2 + salt/iv), расшифровка возможна только с тем же `Secret`.
- **Безопасность**: фреймы > 1MB приводят к закрытию соединения.
- **Backpressure**:
  - если WS не успевает принимать, TCP сокет временно `pause()` до снижения `bufferedAmount`.
  - если TCP не успевает принимать, WS->TCP сообщения временно буферизуются; при переполнении закрываем соединение.
- **Reconnect** (клиент): экспоненциальная задержка 0.5s → 1s → 2s → 5s → 10s.
- **Сигналинг WebRTC (через WS proxy)**:
  - сервер маршрутизирует `voice:*`, `webrtc:*`, `call:*`, `e2ee:*` сообщения по `from/to`;
  - сервер не хранит SDP/ICE, только пересылает.

## Запуск
1. Установить зависимости:

```bash
npm install
```

2. Запустить C++ TCP сервер отдельно.

3. Запустить proxy + статику:

```bash
TCP_HOST=127.0.0.1 TCP_PORT=9000 npm start
```

4. Открыть в браузере:

```
http://localhost:3000
```

5. Открыть 2 вкладки, ввести разные никнеймы, проверить broadcast.

Для личных сообщений укажите `Кому` (никнейм получателя). Чтобы отправить всем — оставьте поле пустым или укажите `всем`.
Для шифрования личных сообщений заполните `Секрет` одинаковым значением у отправителя и получателя.
Опция показа заглушки включает отображение текста для зашифрованных сообщений, иначе показываются маски.
Личные сообщения на сервер уходят как `@name message` (это ожидаемый формат C++ сервера).
Подключение выполняется кнопкой `Подключиться`, а никнейм блокируется до отключения.
Список `Кому` синхронизируется через служебные сообщения `::who::`/`::iam::` при подключении.

## Voice + Calls
- **Voice комнаты**: WebRTC mesh до `VOICE_LIMIT` участников (по умолчанию 6). При превышении выводится предупреждение.
- **Личные звонки 1-на-1**:
  - инициатор делает `call:invite`, получатель видит входящий звонок и отвечает;
  - offer создаёт только инициатор;
  - при неответе 30 секунд звонок отменяется автоматически.
- **Шифрование**:
  - базово медиа защищено DTLS-SRTP (всегда);
  - сигналинг требует WSS/HTTPS на проде;
  - опционально: E2EE (Encoded Transforms + ECDH P-256 + AES-GCM).
- **Звуки событий**:
  - ringtone/ringback генерируются Web Audio API;
  - из-за autoplay policy при первом звонке может потребоваться клик по “Enable sounds”.
- **DND/Busy/Block**:
  - DND автоматически отклоняет входящие;
  - при активном звонке входящие получают `busy`;
  - Block хранится в `localStorage`.

## WebRTC (сигналинг)
Сообщения JSON через WS:
```json
{
  "type": "voice:join | voice:leave | voice:state | webrtc:offer | webrtc:answer | webrtc:ice | call:invite | call:ringing | call:accept | call:reject | call:cancel | call:hangup | e2ee:pubkey | e2ee:key",
  "room": "global",
  "from": "clientId",
  "to": "clientId",
  "payload": {}
}
```

**Кто делает offer:**
- голосовая комната: offer делает участник с меньшим `clientId` (лексикографически);
- личный звонок: offer делает только инициатор `call:invite`.

## HTTPS/WSS
`getUserMedia` работает только в secure context: `https://` или `http://localhost`.
- Для HTTPS режима у proxy:
  - задайте `CERT_PATH` и `KEY_PATH`;
  - при HTTPS WebSocket работает на том же порту, что и HTTP.
- Для продакшна: используйте nginx + Let's Encrypt, проксируйте `/` и WebSocket upgrade.

Пример nginx (упрощенно):
```nginx
server {
  listen 443 ssl;
  server_name your-domain.com;

  ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
  }
}
```

## TURN
Добавьте TURN в ICE через env:
```
TURN_URL=turn:turn.example.com:3478
TURN_USER=turnuser
TURN_PASS=turnpass
```

## Тест-план
1) **Voice**: 2 вкладки → Join Voice → убедиться, что слышно и видно speaking индикатор.
2) **Calls**:
   - исходящий → Accept → аудио работает;
   - Reject/Cancel/Timeout → UI очищается;
   - Busy/DND → корректный reject;
   - Block → входящие отклоняются с reason `blocked`.
3) **E2EE**:
   - включить `E2EE (extra)` в обеих вкладках → статус `E2EE enabled`, звук работает;
   - если браузер не поддерживает — fallback на `Transport encrypted`.

## Smoke-test (env checks)
Скрипт `npm test` проверяет наличие ключевых файлов и конфигурации.

Переменные для расширенных проверок:
- `SMOKE_STRICT=1` — считать предупреждения ошибками.
- `SMOKE_CHECK_TCP=1` — проверить TCP доступность `TCP_HOST`/`TCP_PORT` (timeout 2s).
- `SMOKE_CHECK_WS=1` — проверить, что порт WS доступен.
- `SMOKE_CHECK_WS_HANDSHAKE=1` — выполнить полноценный WS handshake.
- `SMOKE_WS_HOST`, `SMOKE_WS_PORT` — override хоста/порта для WS проверок.

Примеры:
```bash
SMOKE_STRICT=1 npm test
SMOKE_CHECK_TCP=1 TCP_HOST=127.0.0.1 TCP_PORT=9000 npm test
SMOKE_CHECK_WS=1 SMOKE_CHECK_WS_HANDSHAKE=1 npm test
```

## Авторизация
- Вход/регистрация реализованы на backend (Express) с хранением пользователей в `data/users.json`.
- Пароль должен быть минимум 8 символов и содержать строчные, заглавные буквы и цифры.
- Сессия хранится в `localStorage` и проверяется через `/api/me`.

## Порты
- HTTP (статика): `3000`
- WebSocket proxy (HTTP): `8080`
- WebSocket proxy (HTTPS): `HTTP_PORT` (общий с HTTPS)

При необходимости можно переопределить `HTTP_PORT` и `WS_PORT`.

## Переменные окружения
- `HTTP_PORT`, `WS_PORT`
- `TCP_HOST`, `TCP_PORT`
- `CERT_PATH`, `KEY_PATH` (HTTPS режим)
- `TURN_URL`, `TURN_USER`, `TURN_PASS`
- `VOICE_LIMIT`
