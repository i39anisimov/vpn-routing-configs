# Контекст проекта

Этот файл содержит контекст для Claude Code: состав категорий, политики
конфигов, порядок проверки и ограничения. Общее описание и структура проекта —
в `README.md`.

Дата сверки: **2026-11-10**. Версии upstream-списков blackmatrix7:
Claude/OpenAI/YouTube/Instagram — 2025-06-06, Telegram — 2025-09-10.

## Категории

| № | Файл | Правил | Что входит | `shadowrocket_home.conf` | `shadowrocket_general.conf` |
|---|---|---|---|---|---|
| 1 | `rules/ru.list` | 65 | `GEOIP,RU`, национальные зоны `.ru`/`.su`/`.moscow`/IDN и российские сервисы: Яндекс, VK, маркетплейсы, ритейл, Сбер и др. | `DIRECT` | `DIRECT` |
| 2 | `rules/ai.list` | 157 | blackmatrix7 Claude (3) и OpenAI (35), плюс прочие AI-сервисы: Gemini, Copilot, Grok, Perplexity, DeepSeek, Mistral, Hugging Face, Midjourney, ElevenLabs и др. | `PROXY` | `PROXY` |
| 3 | `rules/telegram.list` | 52 | blackmatrix7 Telegram (40), 6 дополнительных IP-диапазонов, Telegram-порты голосовых звонков | `PROXY` | `PROXY` |
| 4 | `rules/youtube.list` | 190 | blackmatrix7 YouTube: домены `youtube.*`, Googlevideo, YT CDN, `USER-AGENT` и IP-диапазоны | `DIRECT` | `PROXY` |
| 5 | `rules/instagram.list` | 5 | blackmatrix7 Instagram: `instagram.com`, `cdninstagram.com`, `instagr.am`, ключевое слово `instagram`; AS32934 Meta для CDN и медиа | `DIRECT` | `PROXY` |
| — | `FINAL` | — | всё, что не попало в категории | `DIRECT` | `PROXY` |

Порядок правил в обоих конфигах: **REJECT → 1 → 2 → 3 → 4 → 5 → FINAL**.
Внешний REJECT-список идёт первым и блокирует рекламу и трекеры раньше всех
остальных правил. RU-правила идут следующими, чтобы российские адреса не
перехватывались категориями 2–5. AI-правила идут раньше YouTube — это
страховка на случай пересечений конкретных AI-доменов с широкими правилами
YouTube.

### Состав категорий

| Категория | Что входит | Источник |
|---|---|---|
| 1 — RU | `GEOIP,RU`, национальные зоны РФ и крупные российские сервисы | вручную |
| 2 — AI | Claude и OpenAI | `blackmatrix7/ios_rule_script` |
| 2 — AI | прочие AI-сервисы: Gemini, Copilot, Grok, Perplexity, DeepSeek, Mistral, Hugging Face, Midjourney, ElevenLabs и др. | вручную |
| 3 — Telegram | домены Telegram | `blackmatrix7/ios_rule_script` |
| 3 — Telegram | дополнительные IP-диапазоны и порты голосовых звонков | вручную |
| 4 — YouTube | домены, CDN, `USER-AGENT` и IP-диапазоны YouTube | `blackmatrix7/ios_rule_script` |
| 5 — Instagram | домены Instagram и `IP-ASN,32934` Meta для CDN и медиа | `blackmatrix7/ios_rule_script` + вручную |

### Внешний REJECT-список

До блока `GENERATED RULES` в обоих конфигах подключён внешний список рекламы
и трекеров:

```
RULE-SET,https://raw.githubusercontent.com/zeklop/shadowrocket-configs/refs/heads/main/REJECT.list,REJECT
```

Он не входит в `rules/` и не считается категорией: политика `REJECT`, первый
приоритет. Список обновляется на стороне источника, локальная копия не нужна.

Списки заблокированных в РФ ресурсов, Discord, geo-detect, ipchecker и
custom-proxy в категории не входят: это не российские адреса и не
AI/Telegram/YouTube/Instagram. В `shadowrocket_home.conf` они ходят напрямую
через `FINAL,DIRECT`, в `shadowrocket_general.conf` — через прокси через
`FINAL,PROXY`.

## Конфиги

Конфиги не дублируют правила: в `[Rule]` подключены пять внутренних
`RULE-SET`-ссылок на файлы `rules/*.list` и один внешний REJECT RULE-SET.
Блок генерируется скриптом из `repo.json`:

```
RULE-SET,https://raw.githubusercontent.com/zeklop/shadowrocket-configs/refs/heads/main/REJECT.list,REJECT

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
`--write` из `repo.json`. В `shadowrocket_general.conf` те же ссылки, но YouTube
идёт в `PROXY`, а `FINAL` — `FINAL,PROXY`.

**Репозиторий должен быть публичным**, иначе `raw.githubusercontent.com`
не отдаст файлы правил без токена. `update-url` в каждом конфиге указывает
на его собственный raw-URL, поэтому Shadowrocket может обновлять конфиг.

### `shadowrocket_home.conf` — домашний режим

- внешний REJECT-список — `REJECT` (первый приоритет)
- категория 1 (RU) — `DIRECT`
- категория 2 (AI) — `PROXY`
- категория 3 (Telegram) — `PROXY`
- категория 4 (YouTube) — `DIRECT`
- категория 5 (Instagram) — `DIRECT`
- всё остальное — `DIRECT` (`FINAL,DIRECT`)

### `shadowrocket_general.conf` — общий режим

- внешний REJECT-список — `REJECT` (первый приоритет)
- категория 1 (RU) — `DIRECT`
- категория 2 (AI) — `PROXY`
- категория 3 (Telegram) — `PROXY`
- категория 4 (YouTube) — `PROXY`
- категория 5 (Instagram) — `PROXY`
- всё остальное — `PROXY` (`FINAL,PROXY`)

Остальные настройки `[General]` одинаковые в обоих конфигах. Секции
`[Proxy Group]` нет: используются встроенные политики `DIRECT` и `PROXY`.
`include` не используется; правила подключаются через `RULE-SET`,
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

## Профили Happ

`happ/happ-home.json` и `happ/happ-general.json` — профили маршрутизации
клиента Happ, аналогичные двум Shadowrocket-конфигам. Формат описан в
[документации Happ](https://www.happ.su/main/ru/dev-docs/routing.md): JSON
в CamelCase, «булевы» значения — строки (`"true"`/`"false"`), списки
заполняются тегами `geosite:`/`geoip:`. Legacy-ключи `RemoteDns` и
`DomesticDns` допустимы — они есть в примере экспорта из документации.

Оба профиля используют базы
[`hydraponique/roscomvpn-geoip`](https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geoip@202611101104/release/geoip.dat)
и
[`hydraponique/roscomvpn-geosite`](https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geosite@202610120948/release/geosite.dat).
Удалённый DNS — Google DoH (`8.8.8.8`), локальный — Yandex DoH
(`77.88.8.8`), `DomainStrategy` — `IPIfNonMatch`, `FakeDNS` — `"false"`.

| Профиль | `RouteOrder` | Direct | Proxy |
|---|---|---|---|
| `happ-home.json` | `block-direct-proxy` | `private`, `category-ru`, `whitelist`, `microsoft`, `apple`, `epicgames`, `riot`, `escapefromtarkov`, `steam`, `twitch`, `pinterest`, `faceit`, `youtube` + `geoip:private`, `geoip:direct` | `google-play`, `github`, `twitch-ads`, `telegram` |
| `happ-general.json` | `block-proxy-direct` | то же, без `youtube` | то же + `youtube` |

`BlockSites` в обоих — `win-spy`, `torrent`, `category-ads`.

Особенности:

- `GlobalProxy: "true"` в обоих профилях: всё, что не попало ни в один
  список, идёт через прокси. Поэтому домашний профиль Happ проксирует
  неописанный трафик, в отличие от `FINAL,DIRECT` в `shadowrocket_home.conf`.
- В базе `roscomvpn-geosite` **нет тега `INSTAGRAM`** и AI-тегов (`openai`,
  `anthropic` и т. п.). Instagram идёт по fallback (через прокси), AI тоже
  проксируется за счёт `GlobalProxy`. Строки с несуществующими тегами не
  добавлять: правило молча не срабатывает.
- Сверка тегов: в базе 24 тега geosite (`APPLE`, `CATEGORY-ADS`,
  `CATEGORY-GEOBLOCK-RU`, `CATEGORY-RU`, `EPICGAMES`, `ESCAPEFROMTARKOV`,
  `FACEIT`, `GITHUB`, `GOOGLE-DEEPMIND`, `GOOGLE-PLAY`, `MICROSOFT`, `ORIGIN`,
  `PINTEREST`, `PRIVATE`, `PUSH`, `RIOT`, `STEAM`, `TELEGRAM`, `TORRENT`,
  `TWITCH`, `TWITCH-ADS`, `WHITELIST`, `WIN-SPY`, `YOUTUBE`) и три тега geoip
  (`DIRECT`, `PRIVATE`, `WHITELIST`).

Импорт — ссылкой `happ://routing/onadd/<base64>`, где base64 стандартный
(с padding) от содержимого JSON-файла. Ссылки опубликованы в `README.md`;
после изменения профиля их нужно перегенерировать:

```bash
base64 < happ/happ-home.json | tr -d '\n'
base64 < happ/happ-general.json | tr -d '\n'
```

`scripts/validate.py` проверяет только Shadowrocket-конфиги и `rules/*.list`;
профили Happ он не валидирует.

## Рабочий процесс

```bash
python3 scripts/validate.py          # только проверить
python3 scripts/validate.py --write  # проверить и пересобрать блоки правил
python3 scripts/validate.py --strict # предупреждения считать ошибками
```

Запускать **после любого добавления/изменения правил**. Рекомендуемый порядок:

1. Добавить или изменить правило в `rules/ru.list`, `ai.list`, `telegram.list`,
   `youtube.list` или `instagram.list`.
2. Выполнить `python3 scripts/validate.py --write`.
3. Убедиться, что скрипт завершился с кодом `0` и написал `Ошибок: 0`.
4. Закоммитить изменения и выполнить `git push` — устройства читают правила
   по raw-URL из GitHub.
5. В Shadowrocket обновить конфиг или дождаться обновления `RULE-SET`.

`--write` обновляет `# TOTAL:` и `# UPDATED:` в заголовках списков, а также
пересобирает блоки `RULE-SET` и `update-url` в обоих конфигах из `repo.json`.
Если в правилах есть ошибка, запись не выполняется.

Не редактировать строки внутри маркеров
`# >>> GENERATED RULES: BEGIN >>>` / `END` — они перезаписываются. Новые
правила добавлять в соответствующий `rules/*.list`, а не в конфиг.

## Что проверяет скрипт

Списки `rules/*.list`:

- синтаксис `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `IP-CIDR`,
  `IP-CIDR6`, `IP-ASN`, `GEOIP`, `DST-PORT`, `SRC-PORT`, `PROCESS-NAME`,
  `USER-AGENT`, `URL-REGEX`, `DOMAIN-REGEX`;
- корректность доменов (метки, длина, нижний регистр, IDN/punycode),
  IP/CIDR (включая проверку host-bits), ASN, портов и диапазонов;
- запрет политик `DIRECT`/`PROXY` внутри `.list` — политику задаёт конфиг;
- запрет `DOMAIN-SUFFIX` из одного сегмента, кроме национальных зон РФ
  (`ru`, `su`, `moscow`, `xn--p1ai`, `xn--p1acf`, `xn--80adxhks`,
  `xn--80aswg`, `xn--80asehdb`, `xn--d1acj3b`) и gTLD `youtube`;
  запрет публичных суффиксов вроде `com`/`net`/`io`;
- дубликаты внутри файла и одинаковые правила в разных категориях;
- пересечения доменов между категориями (предупреждение);
- обязательные заголовки `# NAME:`, `# SOURCE:`, `# CATEGORY:`, `# TOTAL:`;
- UTF-8 без BOM, переводы строк LF, перевод строки в конце файла.

Конфиги `shadowrocket_home.conf` / `shadowrocket_general.conf`:

- структура секций `[General]` и `[Rule]`; секция `[Proxy Group]` опциональна;
- известные ключи `[General]`, булевы значения, CIDR в `skip-proxy`
  и `tun-excluded-routes`, существование файлов из `include`;
- корректность proxy-групп (если секция есть) и регулярных выражений;
- корректность каждого правила и его политики;
- ровно одно `FINAL`, и оно последнее: `FINAL,DIRECT` для home,
  `FINAL,PROXY` для general;
- вне блока `GENERATED RULES` допускаются только внешний REJECT RULE-SET
  (строго до блока) и `FINAL`;
- ровно пять внутренних `RULE-SET`-ссылок в порядке категорий, с URL
  из `repo.json` и ожидаемыми политиками, плюс ровно один внешний REJECT
  RULE-SET до блока;
- `update-url` указывает на raw-URL самого конфига;
- одинаковость `[General]` в двух конфигах
  (предупреждение при расхождении).

Коды возврата: `0` — всё корректно, `1` — есть ошибки,
`2` — не удалось запуститься (например, нет каталога `rules/`).

## Требования Shadowrocket

- Для правила `GEOIP,RU` нужна база **GeoLite2 Country**:
  `Settings → GeoLite2 Database`.
- Для правил `IP-ASN` нужна база **GeoLite2 ASN** (там же). Это касается
  5 ASN Telegram, ASN 20473 из OpenAI-списка и ASN 32934 (Meta/Instagram).
  Без базы эти правила не сработают, остальные правила продолжат работать.
- Политика `PROXY` означает выбранный в Shadowrocket сервер/подписку.
- Импорт: `Config → +` → указать файл или URL конфига.

## Оговорки

- **Категория 1 перехватывает все `.ru`-домены** через `DOMAIN-SUFFIX,ru`
  раньше остальных категорий, поэтому `youtube.ru` и заблокированные
  `.ru`-сайты пойдут в `DIRECT`. Дополнительно перечислены национальные
  зоны РФ (`.su`, `.moscow`, IDN) и не-`.ru` домены крупных российских
  сервисов; остальные российские адреса покрывает `GEOIP,RU`.
- **В OpenAI-списке blackmatrix7 есть общие сторонние домены**:
  `stripe.com`, `sentry.io`, `segment.io`, `intercom.io`, `auth0.com`,
  `algolia.net`, `launchdarkly.com`, `statsig.com`, `identrust.com`,
  `featuregates.org`, `observeit.net`, `browser-intake-datadoghq.com`,
  `static.cloudflareinsights.com`. Они попали в AI-категорию, потому что
  используются ChatGPT. В `shadowrocket_home.conf` они будут ходить через
  прокси; если это нежелательно, удалите их из `rules/ai.list` и выполните
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
