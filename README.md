# VPN routing configs для Shadowrocket

Два готовых конфига для Shadowrocket. Списки правил для Telegram, Claude,
OpenAI, YouTube и Instagram взяты из
[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script);
российские адреса и прочие AI-сервисы поддерживаются вручную в `rules/*.list`.
Правила разбиты на пять категорий, конфиги проверяются и пересобираются скриптом.

Дата сверки: **2026-11-10**. Версии upstream-списков blackmatrix7:
Claude/OpenAI/YouTube/Instagram — 2025-06-06, Telegram — 2025-09-10.

## Структура

```
.
├── shadowrocket_home.conf      # домашний режим
├── shadowrocket_general.conf   # общий режим
├── repo.json                   # owner/repo/branch для raw-ссылок
├── rules/
│   ├── ru.list                 # категория 1: российские адреса
│   ├── ai.list                 # категория 2: AI-сервисы
│   ├── telegram.list           # категория 3: Telegram
│   ├── youtube.list            # категория 4: YouTube
│   └── instagram.list          # категория 5: Instagram
└── scripts/
    └── validate.py             # проверка и пересборка конфигов
```

## Категории

| № | Файл | Правил | Что входит | `shadowrocket_home.conf` | `shadowrocket_general.conf` |
|---|---|---|---|---|---|
| 1 | `rules/ru.list` | 1115 | `GEOIP,RU`, домены российских банков (список ЦБ РФ), `.рф`/`.su`, крупные российские сервисы на не-`.ru` доменах | `DIRECT` | `DIRECT` |
| 2 | `rules/ai.list` | 157 | blackmatrix7 Claude (3) и OpenAI (35), плюс прочие AI-сервисы: Gemini, Copilot, Grok, Perplexity, DeepSeek, Mistral, Hugging Face, Midjourney, ElevenLabs и др. | `PROXY` | `PROXY` |
| 3 | `rules/telegram.list` | 52 | blackmatrix7 Telegram (40), 6 дополнительных IP-диапазонов, Telegram-порты голосовых звонков | `PROXY` | `PROXY` |
| 4 | `rules/youtube.list` | 190 | blackmatrix7 YouTube: домены `youtube.*`, Googlevideo, YT CDN, `USER-AGENT` и IP-диапазоны | `DIRECT` | `PROXY` |
| 5 | `rules/instagram.list` | 5 | blackmatrix7 Instagram: `instagram.com`, `cdninstagram.com`, `instagr.am`, ключевое слово `instagram`; AS32934 Meta для CDN и медиа | `DIRECT` | `PROXY` |
| — | `FINAL` | — | всё, что не попало в категории | `DIRECT` | `PROXY` |

Порядок правил в обоих конфигах: **1 → 2 → 3 → 4 → 5 → FINAL**. RU-правила
идут первыми, чтобы российские адреса не перехватывались категориями 2–5.
AI-правила идут раньше YouTube — это страховка на случай пересечений
конкретных AI-доменов с широкими правилами YouTube.

### Состав категорий

| Категория | Что входит | Источник |
|---|---|---|
| 1 — RU | `GEOIP,RU`, домены банков ЦБ РФ, `.рф`/`.su`, крупные российские сервисы | вручную |
| 2 — AI | Claude и OpenAI | `blackmatrix7/ios_rule_script` |
| 2 — AI | прочие AI-сервисы: Gemini, Copilot, Grok, Perplexity, DeepSeek, Mistral, Hugging Face, Midjourney, ElevenLabs и др. | вручную |
| 3 — Telegram | домены Telegram | `blackmatrix7/ios_rule_script` |
| 3 — Telegram | дополнительные IP-диапазоны и порты голосовых звонков | вручную |
| 4 — YouTube | домены, CDN, `USER-AGENT` и IP-диапазоны YouTube | `blackmatrix7/ios_rule_script` |
| 5 — Instagram | домены Instagram и `IP-ASN,32934` Meta для CDN и медиа | `blackmatrix7/ios_rule_script` + вручную |

Списки заблокированных в РФ ресурсов, Discord, geo-detect, ipchecker и
custom-proxy в категории не входят: это не российские адреса и не
AI/Telegram/YouTube/Instagram. В `shadowrocket_home.conf` они ходят напрямую через
`FINAL,DIRECT`, в `shadowrocket_general.conf` — через прокси через `FINAL,PROXY`.

## Конфиги

Конфиги не дублируют правила: в `[Rule]` подключены пять `RULE-SET`-ссылок
на файлы `rules/*.list` в этом репозитории. Блок генерируется скриптом
из `repo.json`:

```
# >>> GENERATED RULES: BEGIN >>>

# [1/5] RU-адреса -> DIRECT
RULE-SET,https://raw.githubusercontent.com/<owner>/<repo>/main/rules/ru.list,DIRECT

# [2/5] AI -> PROXY
RULE-SET,https://raw.githubusercontent.com/<owner>/<repo>/main/rules/ai.list,PROXY

# [3/5] Telegram -> PROXY
RULE-SET,https://raw.githubusercontent.com/<owner>/<repo>/main/rules/telegram.list,PROXY

# [4/5] YouTube -> DIRECT
RULE-SET,https://raw.githubusercontent.com/<owner>/<repo>/main/rules/youtube.list,DIRECT

# [5/5] Instagram -> DIRECT
RULE-SET,https://raw.githubusercontent.com/<owner>/<repo>/main/rules/instagram.list,DIRECT

# >>> GENERATED RULES: END <<<
FINAL,DIRECT
```

Внутри маркеров строки руками не редактируют: они пересобираются командой
`--write` из `repo.json`. В `shadowrocket_general.conf` те же ссылки, но YouTube идёт
в `PROXY`, а `FINAL` — `FINAL,PROXY`.

**Репозиторий должен быть публичным**, иначе `raw.githubusercontent.com`
не отдаст файлы правил без токена. `update-url` в каждом конфиге указывает
на его собственный raw-URL, поэтому Shadowrocket может обновлять конфиг.

### `shadowrocket_home.conf` — домашний режим

- категория 1 (RU) — `DIRECT`
- категория 2 (AI) — `PROXY`
- категория 3 (Telegram) — `PROXY`
- категория 4 (YouTube) — `DIRECT`
- категория 5 (Instagram) — `DIRECT`
- всё остальное — `DIRECT` (`FINAL,DIRECT`)

### `shadowrocket_general.conf` — общий режим

- категория 1 (RU) — `DIRECT`
- категория 2 (AI) — `PROXY`
- категория 3 (Telegram) — `PROXY`
- категория 4 (YouTube) — `PROXY`
- категория 5 (Instagram) — `PROXY`
- всё остальное — `PROXY` (`FINAL,PROXY`)

Остальные настройки `[General]` и `[Proxy Group]` одинаковые в обоих
конфигах. `include` отключён; правила подключаются через `RULE-SET`,
а `update-url` указывает на raw-URL конфига в этом репозитории.

### `repo.json`

```json
{
  "owner": "ваш-github-логин",
  "repo": "vpn-routing-configs",
  "branch": "main"
}
```

Из этих полей собираются все `RULE-SET`-ссылки и `update-url`. После изменения
`repo.json` выполните `python3 scripts/validate.py --write`.

## Скрипт проверки

```bash
python3 scripts/validate.py          # только проверить
python3 scripts/validate.py --write  # проверить и пересобрать блоки правил
python3 scripts/validate.py --strict # предупреждения считать ошибками
```

Запускать **после любого добавления/изменения правил**. Рекомендуемый порядок:

1. Добавить или изменить правило в `rules/ru.list`, `ai.list`, `telegram.list`
   или `youtube.list`.
2. Выполнить `python3 scripts/validate.py --write`.
3. Убедиться, что скрипт завершился с кодом `0` и написал `Ошибок: 0`.
4. Закоммитить изменения и выполнить `git push` — устройства читают правила
   по raw-URL из GitHub.
5. В Shadowrocket обновить конфиг или дождаться обновления `RULE-SET`.

`--write` обновляет `# TOTAL:` и `# UPDATED:` в заголовках списков, а также
пересобирает блоки `RULE-SET` и `update-url` в обоих конфигах из `repo.json`.
Если в правилах есть ошибка, запись не выполняется.

### Что проверяется

Списки `rules/*.list`:

- синтаксис `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `IP-CIDR`,
  `IP-CIDR6`, `IP-ASN`, `GEOIP`, `DST-PORT`, `SRC-PORT`, `PROCESS-NAME`,
  `USER-AGENT`, `URL-REGEX`, `DOMAIN-REGEX`;
- корректность доменов (метки, длина, нижний регистр, IDN/punycode),
  IP/CIDR (включая проверку host-bits), ASN, портов и диапазонов;
- запрет политик `DIRECT`/`PROXY` внутри `.list` — политику задаёт конфиг;
- запрет `DOMAIN-SUFFIX` из одного сегмента, кроме `ru`, `su`, `рф`,
  `xn--p1ai`, `youtube`, и запрет публичных суффиксов вроде `com`/`net`/`io`;
- дубликаты внутри файла и одинаковые правила в разных категориях;
- пересечения доменов между категориями (предупреждение);
- обязательные заголовки `# NAME:`, `# SOURCE:`, `# CATEGORY:`, `# TOTAL:`;
- UTF-8 без BOM, переводы строк LF, перевод строки в конце файла.

Конфиги `shadowrocket_home.conf` / `shadowrocket_general.conf`:

- структура секций `[General]`, `[Proxy Group]`, `[Rule]`;
- известные ключи `[General]`, булевы значения, CIDR в `skip-proxy`
  и `tun-excluded-routes`, существование файлов из `include`;
- корректность proxy-групп и регулярных выражений;
- корректность каждого правила и его политики;
- ровно одно `FINAL`, и оно последнее: `FINAL,DIRECT` для home,
  `FINAL,PROXY` для general;
- отсутствие правил вне блока `RULE-SET`;
- ровно пять `RULE-SET`-ссылок в порядке категорий, с URL из `repo.json`
  и ожидаемыми политиками;
- `update-url` указывает на raw-URL самого конфига;
- одинаковость `[General]` и `[Proxy Group]` в двух конфигах
  (предупреждение при расхождении).

Коды возврата: `0` — всё корректно, `1` — есть ошибки,
`2` — не удалось запуститься (например, нет каталога `rules/`).

## Требования Shadowrocket

- Для правила `GEOIP,RU` нужна база **GeoLite2 Country**:
  `Settings → GeoLite2 Database`. Ссылки на mmdb есть в комментариях конфига.
- Для правил `IP-ASN` нужна база **GeoLite2 ASN** (там же). Это касается
  5 ASN Telegram, ASN 20473 из OpenAI-списка и ASN 32934 (Meta/Instagram).
  Без базы эти правила не сработают, остальные правила продолжат работать.
- Политика `PROXY` означает выбранный в Shadowrocket сервер/подписку.
- Импорт: `Config → +` → указать файл или URL конфига.

## Оговорки

- **Нет общего правила `DOMAIN-SUFFIX,ru`.** Это сделано специально:
  иначе `youtube.ru` и заблокированные `.ru`-сайты попадали бы в `DIRECT`
  раньше своих категорий. Российские адреса определяются через `GEOIP,RU`
  и явные домены. В home всё остальное и так идёт напрямую, в general —
  через прокси по `FINAL,PROXY`.
- **В OpenAI-списке blackmatrix7 есть общие сторонние домены**:
  `stripe.com`, `sentry.io`, `segment.io`, `intercom.io`, `auth0.com`,
  `algolia.net`, `launchdarkly.com`, `statsig.com`, `identrust.com`,
  `featuregates.org`, `observeit.net`, `browser-intake-datadoghq.com`,
  `static.cloudflareinsights.com`. Они попали в AI-категорию, потому что
  используются ChatGPT. В `shadowrocket_home.conf` они будут ходить через прокси;
  если это нежелательно, удалите их из `rules/ai.list` и выполните
  `python3 scripts/validate.py --write`.
- **В Claude-списке** есть `cdn.usefathom.com` (аналитика) — по той же причине
  он тоже попал в AI-категорию.
- **YouTube-список содержит `USER-AGENT`-правила** для приложений YouTube
  и YouTube Music. Они срабатывают по User-Agent, а не по DNS.
  `DOMAIN-SUFFIX,youtube` — это gTLD, поэтому он разрешён валидатором
  как single-label суффикс.
- **YouTube напрямую в `shadowrocket_home.conf`** может работать медленно или
  нестабильно в РФ — это ожидаемое следствие выбранной схемы.
- **Instagram-категория использует `IP-ASN,32934`** (Meta) для CDN и медиа,
  поэтому вместе с Instagram в неё попадают Facebook, WhatsApp и Threads.
  Если нужны только домены Instagram, удалите строку `IP-ASN,32934`
  из `rules/instagram.list` и выполните `python3 scripts/validate.py --write`.
- **`apple-relay.apple.com`** оставлен в AI-категории.
- Категории 2–5 не являются полными списками всех сервисов: это
  upstream-списки blackmatrix7 плюс дополнения. Новые правила добавляйте
  в соответствующий `rules/*.list`, а не в конфиг.

## Источники

- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script),
  каталог `rule/Shadowrocket` (пять списков):
  - `Claude/Claude.list` — upstream 2025-06-06;
  - `OpenAI/OpenAI.list` — upstream 2025-06-06;
  - `Telegram/Telegram.list` — upstream 2025-09-10;
  - `YouTube/YouTube.list` — upstream 2025-06-06;
  - `Instagram/Instagram.list` — upstream 2025-06-06.

Остальные правила ведутся вручную в `rules/*.list`. Списки blackmatrix7
зафиксированы на 2026-11-10.
