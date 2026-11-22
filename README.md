# keygate

Единый gateway для API-ключей. Наружу отдаётся один мастер-ключ, внутри — провайдеры (Telegram, OpenAI, AWS, Anthropic), правила доступа, лимиты и аудит.

Ключи наружу не уходят. Клиент получает временный lease и замаскированный ключ.

## Устройство

- **Go** — HTTP-шлюз: авторизация, rate limit, аудит, выдача lease.
- **Rust** — policy engine. Решения принимаются через C ABI, без внешних зависимостей.
- **SDK**: Python, Java, PHP, C++.
- Docker и GitHub Actions.

## Запуск

```bash
make test
make run
```

Или отдельно:

```bash
cargo build --release --manifest-path rust/Cargo.toml
cd go && go run ./cmd/gateway -config ../config/keygate.conf
```

Docker:

```bash
docker build -t keygate .
docker run --rm -p 8080:8080 keygate
```

## API

Все запросы, кроме `/healthz`, требуют заголовок `X-KeyGate-Key`.

| Метод | Путь | Что делает |
| ----- | ---- | ---------- |
| GET | `/healthz` | проверка |
| POST | `/v1/keys/resolve` | выдать lease на ключ |
| POST | `/v1/keys/rotate` | ротировать ключ провайдера |
| GET | `/v1/audit` | лог событий |
| GET | `/v1/providers` | список провайдеров |
| GET | `/v1/metrics` | метрики |

Пример:

```bash
curl -X POST http://127.0.0.1:8080/v1/keys/resolve \
  -H 'X-KeyGate-Key: kg_master_local' \
  -H 'Content-Type: application/json' \
  -d '{"provider":"telegram","scope":"send","ttl":60}'
```

Ответ:

```json
{
  "lease": "kg_lease_...",
  "provider": "telegram",
  "masked_key": "1234...OKEN",
  "expires_at": "...",
  "decision": {"allow": true, "effective_ttl": 60}
}
```

## Настройки

`config/keygate.conf`:

```ini
addr=:8080
master_key=kg_master_local
allowed_providers=telegram,openai,aws,anthropic
allowed_scopes=read,send,admin
max_ttl=300
deny_unknown=true
rate_per_minute=60
provider.telegram=...
```

## SDK

Python:

```python
from keygate import KeyGateClient
client = KeyGateClient()
print(client.resolve("telegram", "send", 60))
```

Java / PHP / C++ — в `sdk/` и `examples/`.

## Тесты

```bash
make test
make demo
```

Репозиторий: https://github.com/acciv/keygate

Сделал acciv.
