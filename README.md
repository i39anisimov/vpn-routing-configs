# VPN routing configs для Shadowrocket

Проект хранит два готовых конфига маршрутизации для Shadowrocket:
`shadowrocket_home.conf` — домашний режим и `shadowrocket_general.conf` —
общий режим. В обоих российские адреса идут напрямую, AI и Telegram — через
прокси. В домашнем режиме YouTube и Instagram также идут напрямую, в общем —
через прокси.

Правила не хранятся в конфигах: они разбиты на пять категорий в `rules/`
и подключаются через `RULE-SET` по raw-URL этого репозитория. Поэтому
репозиторий должен быть публичным. Первым по приоритету в обоих конфигах
подключён внешний REJECT-список рекламы и трекеров. Конфиги проверяются
и пересобираются скриптом `scripts/validate.py`.

## Структура

```
.
├── README.md                  # описание проекта и структура
├── CLAUDE.md                  # контекст: категории, политики, проверка, оговорки
├── shadowrocket_home.conf     # домашний режим
├── shadowrocket_general.conf  # общий режим
├── repo.json                  # owner/repo/branch для raw-ссылок
├── rules/
│   ├── ru.list                # категория 1: российские адреса
│   ├── ai.list                # категория 2: AI-сервисы
│   ├── telegram.list          # категория 3: Telegram
│   ├── youtube.list           # категория 4: YouTube
│   └── instagram.list         # категория 5: Instagram
├── scripts/
│   └── validate.py            # проверка и пересборка конфигов
└── .github/
    └── workflows/
        └── validate.yml       # CI-проверка при push и pull request
```

Подробности о категориях, политиках, порядке проверки и ограничениях —
в [CLAUDE.md](CLAUDE.md).
