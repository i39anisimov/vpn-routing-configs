# VPN routing configs для Shadowrocket

Два готовых конфига на основе правил
[misha-tgshv/shadowrocket-configuration-file](https://github.com/misha-tgshv/shadowrocket-configuration-file)
и актуальных списков
[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)
для Telegram, Claude, OpenAI и YouTube. Правила разбиты на четыре категории,
конфиги проверяются и пересобираются скриптом.

Дата сверки: **2026-11-10**. Версии upstream-списков blackmatrix7:
Claude/OpenAI/YouTube — 2025-06-06, Telegram — 2025-09-10.

## Структура

```
.
├── ivn_home.conf              # домашний режим
├── ivn_general.conf           # общий режим
├── repo.json                  # owner/repo/branch для raw-ссылок
├── rules/
│   ├── ru.list                # категория 1: российские адреса
│   ├── ai.list                # категория 2: AI-сервисы
│   ├── telegram.list          # категория 3: Telegram
│   └── youtube.list           # категория 4: YouTube
└── scripts/
    └── validate.py            # проверка и пересборка конфигов
```

## Категории

| № | Файл | Правил | Что входит | `ivn_home.conf` | `ivn_general.conf` |
|---|------|--------|------------|-----------------|--------------------|
| 1 | `rules/ru.list` | 1115 | `GEOIP,RU`, домены российских банков (список ЦБ РФ), `.рф`/`.su`, крупные российские сервисы на не-`.ru` доменах | `DIRECT` | `DIRECT` |
| 2 | `rules/ai.list` | 157 | blackmatrix7 Claude (3) и OpenAI (35), плюс прочие AI-сервисы: Gemini, Copilot, Grok, Perplexity, DeepSeek, Mistral, Hugging Face, Midjourney, ElevenLabs и др. | `PROXY` | `PROXY` |
| 3 | `rules/telegram.list` | 52 | blackmatrix7 Telegram (40), 6 дополнительных IP-диапазонов zkeen, Telegram-порты голосовых звонков | `PROXY` | `PROXY` |
| 4 | `rules/youtube.list` | 190 | blackmatrix7 YouTube: домены `youtube.*`, Googlevideo, YT CDN, `USER-AGENT` и IP-диапазоны | `DIRECT` | `PROXY` |
| — | `FINAL` | — | всё, что не попало в категории | `DIRECT` | `PROXY` |

Порядок правил в обоих конфигах: **1 → 2 → 3 → 4 → FINAL**. RU-правила идут
первыми, чтобы российские адреса не перехватывались категориями 2–4.
AI-правила идут раньше YouTube — это страховка на случай пересечений
конкретных AI-доменов с широкими правилами YouTube.

### Как разложены исходные файлы

| Исходный файл | Категория | Комментарий |
|---------------|-----------|-------------|
| `rules/domains_banking.list` (misha-tgshv) | 1 — RU | целиком, 1047 правил (сайты банков ЦБ РФ) |
| `blackmatrix7/.../Claude/Claude.list` | 2 — AI | целиком, 3 правила, upstream 2025-06-06 |
| `blackmatrix7/.../OpenAI/OpenAI.list` | 2 — AI | целиком, 35 правил, upstream 2025-06-06 |
| `source/community.list`, раздел `# ai` | 2 — AI | прочие AI-сервисы |
| `source/community.list`, ключевое слово `chatgpt` | 2 — AI | вынесено из раздела `# special` |
| `rules/domains_antifilter.list` | 2 — AI | только точные AI-домены (`gemini.google.com`, `copilot`, `grok`, `sora`, `openrouter` и т. п.) |
| `rules/domains_refilter.list` | 2 — AI | только точные AI-домены и их API/CDN |
| `source/domains.list` | 2 — AI | только AI-сервисы (`chat.com`, `api.jetbrains.ai`, `remove.bg`, `unscreen.com`) |
| `blackmatrix7/.../Telegram/Telegram.list` | 3 — Telegram | целиком, 40 правил, upstream 2025-09-10 |
| `toneywhitez/zkeen_rules/telegram_ips.list` | 3 — Telegram | 6 IP-диапазонов, не покрытых blackmatrix7 |
| `rules/voice_ports.list` | 3 — Telegram | только Telegram-порты: 3478/3480/3484, 596–599, 1400 |
| `blackmatrix7/.../YouTube/YouTube.list` | 4 — YouTube | целиком, 190 правил, upstream 2025-06-06 |
| `rules/domains_youtube.list` (misha-tgshv) | — | заменён на актуальный `YouTube.list` от blackmatrix7 |
| `source/community.list`, раздел `# youtube` | — | заменён на актуальный `YouTube.list` от blackmatrix7 |
| `rules/domains_discord.list` | — | не входит в четыре категории |
| `rules/domains_geo_detect.list` | — | сервисы определения IP/геолокации |
| `rules/domains_ipchecker.list` | — | чекеры IP |
| `rules/custom-proxy.list` | — | ручные proxy-исключения (TikTok, Habr) |
| `rules/domain_ips.list` | — | IP, полученные из `source/domains.list` |
| `rules/ips_antifilter.list` | — | IP-список заблокированных в РФ ресурсов |
| `rules/ips_refilter.list` | — | IP-список Re-filter |
| `rules/domains_antifilter.list`, `rules/domains_refilter.list` (остальное) | — | общие списки заблокированных ресурсов |

Файлы «—» сознательно **не включены** в категории: это не российские адреса
и не AI/Telegram/YouTube. В `ivn_home.conf` они ходят напрямую через
`FINAL,DIRECT`, в `ivn_general.conf` — через прокси через `FINAL,PROXY`.

## Конфиги

Конфиги не дублируют правила: в `[Rule]` подключены четыре `RULE-SET`-ссылки
на файлы `rules/*.list` в этом репозитории. Блок генерируется скриптом
из `repo.json`:

```
# >>> GENERATED RULES: BEGIN >>>

# [1/4] RU-адреса -> DIRECT
RULE-SET,https://raw.githubusercontent.com/<owner>/<repo>/main/rules/ru.list,DIRECT

# [2/4] AI -> PROXY
RULE-SET,https://raw.githubusercontent.com/<owner>/<repo>/main/rules/ai.list,PROXY

# [3/4] Telegram -> PROXY
RULE-SET,https://raw.githubusercontent.com/<owner>/<repo>/main/rules/telegram.list,PROXY

# [4/4] YouTube -> DIRECT
RULE-SET,https://raw.githubusercontent.com/<owner>/<repo>/main/rules/youtube.list,DIRECT

# >>> GENERATED RULES: END <<<
FINAL,DIRECT
```

Внутри маркеров строки руками не редактируют: они пересобираются командой
`--write` из `repo.json`. В `ivn_general.conf` те же ссылки, но YouTube идёт
в `PROXY`, а `FINAL` — `FINAL,PROXY`.

**Репозиторий должен быть публичным**, иначе `raw.githubusercontent.com`
не отдаст файлы правил без токена. `update-url` в каждом конфиге указывает
на его собственный raw-URL, поэтому Shadowrocket может обновлять конфиг.

### `ivn_home.conf` — домашний режим

- категория 1 (RU) — `DIRECT`
- категория 2 (AI) — `PROXY`
- категория 3 (Telegram) — `PROXY`
- категория 4 (YouTube) — `DIRECT`
- всё остальное — `DIRECT` (`FINAL,DIRECT`)

### `ivn_general.conf` — общий режим

- категория 1 (RU) — `DIRECT`
- категория 2 (AI) — `PROXY`
- категория 3 (Telegram) — `PROXY`
- категория 4 (YouTube) — `PROXY`
- всё остальное — `PROXY` (`FINAL,PROXY`)

Остальные настройки `[General]` и `[Proxy Group]` одинаковые и взяты из
`source/General.txt` исходного репозитория. `include` отключён; правила
подключаются через `RULE-SET`, а `update-url` указывает на raw-URL конфига
в этом репозитории.

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

Конфиги `ivn_home.conf` / `ivn_general.conf`:

- структура секций `[General]`, `[Proxy Group]`, `[Rule]`;
- известные ключи `[General]`, булевы значения, CIDR в `skip-proxy`
  и `tun-excluded-routes`, существование файлов из `include`;
- корректность proxy-групп и регулярных выражений;
- корректность каждого правила и его политики;
- ровно одно `FINAL`, и оно последнее: `FINAL,DIRECT` для home,
  `FINAL,PROXY` для general;
- отсутствие правил вне блока `RULE-SET`;
- ровно четыре `RULE-SET`-ссылки в порядке категорий, с URL из `repo.json`
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
  5 ASN Telegram и ASN 20473 из OpenAI-списка. Без базы эти правила
  не сработают, остальные правила продолжат работать.
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
  используются ChatGPT. В `ivn_home.conf` они будут ходить через прокси;
  если это нежелательно, удалите их из `rules/ai.list` и выполните
  `python3 scripts/validate.py --write`.
- **В Claude-списке** есть `cdn.usefathom.com` (аналитика) — по той же причине
  он тоже попал в AI-категорию.
- **YouTube-список содержит `USER-AGENT`-правила** для приложений YouTube
  и YouTube Music. Они срабатывают по User-Agent, а не по DNS.
  `DOMAIN-SUFFIX,youtube` — это gTLD, поэтому он разрешён валидатором
  как single-label суффикс.
- **YouTube напрямую в `ivn_home.conf`** может работать медленно или
  нестабильно в РФ — это ожидаемое следствие выбранной схемы.
- **`apple-relay.apple.com`** оставлен в AI-категории, как в исходном
  community-списке.
- Категории 2–4 не являются полными списками всех сервисов: это
  upstream-списки blackmatrix7 плюс дополнения. Новые правила добавляйте
  в соответствующий `rules/*.list`, а не в конфиг.

## Источники

- [misha-tgshv/shadowrocket-configuration-file](https://github.com/misha-tgshv/shadowrocket-configuration-file) —
  `domains_banking.list`, `domains_youtube.list`, `domains_antifilter.list`,
  `domains_refilter.list`, `voice_ports.list`, `source/community.list`,
  `source/domains.list`, `source/General.txt`.
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script),
  каталог `rule/Shadowrocket` (четыре списка):
  - `Claude/Claude.list` — upstream 2025-06-06;
  - `OpenAI/OpenAI.list` — upstream 2025-06-06;
  - `Telegram/Telegram.list` — upstream 2025-09-10;
  - `YouTube/YouTube.list` — upstream 2025-06-06.
- [toneywhitez/zkeen_rules](https://github.com/toneywhitez/zkeen_rules) —
  `telegram_ips.list`.
- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) —
  источник `domains_geo_detect.list` (в конфиги не включён).
- [1andrevich/Re-filter-lists](https://github.com/1andrevich/Re-filter-lists) —
  источник `domains_refilter.list` / `ips_refilter.list`.

Обновление списков из upstream автоматизировано в исходном репозитории
через GitHub Actions; здесь списки зафиксированы на 2026-11-10.
