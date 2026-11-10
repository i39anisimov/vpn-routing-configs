# VPN routing configs для Shadowrocket и Happ

Проект хранит готовые профили маршрутизации в двух режимах — домашнем и общем —
для двух клиентов: Shadowrocket (`shadowrocket_home.conf`,
`shadowrocket_general.conf`) и Happ (`happ/happ-home.json`,
`happ/happ-general.json`). В обоих режимах российские адреса идут напрямую,
AI и Telegram — через прокси. В домашнем режиме YouTube (а в Shadowrocket —
и Instagram) идёт напрямую, в общем — через прокси.

Правила Shadowrocket не хранятся в конфигах: они разбиты на пять категорий
в `rules/` и подключаются через `RULE-SET` по raw-URL этого репозитория.
Поэтому репозиторий должен быть публичным. Первым по приоритету в обоих
конфигах подключён REJECT-список рекламы и трекеров `rules/reject.list`.
Конфиги проверяются и пересобираются скриптом `scripts/validate.py`.

Профили Happ — самостоятельные JSON-файлы: они опираются на geoip/geosite-базы
`roscomvpn-geoip` и `roscomvpn-geosite` и импортируются ссылкой
`happ://routing/onadd/`, см. [Импорт в Happ](#импорт-в-happ).

## Структура

```
.
├── README.md                  # описание проекта и структура
├── CLAUDE.md                  # контекст: категории, политики, проверка, оговорки
├── shadowrocket_home.conf     # домашний режим для Shadowrocket
├── shadowrocket_general.conf  # общий режим для Shadowrocket
├── happ/
│   ├── happ-home.json         # домашний режим для Happ
│   └── happ-general.json      # общий режим для Happ
├── repo.json                  # owner/repo/branch для raw-ссылок
├── rules/
│   ├── reject.list            # реклама и трекеры (REJECT, первый приоритет)
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

## Импорт в Happ

Профиль Happ — это JSON-файл, который импортируется ссылкой
`happ://routing/onadd/<base64>`, где `<base64>` — содержимое файла,
закодированное base64. Ссылка самодостаточна: скачивать файл из репозитория
не нужно, но автообновления у неё нет — чтобы обновить профиль, импортируйте
ссылку заново (профиль с тем же `Name` перезаписывается).

Ссылку нужно открывать на устройстве с установленным Happ: Safari или другой
браузер предложит открыть её в приложении.

**Домашний режим** — `happ/happ-home.json`:

```
happ://routing/onadd/ewogICJOYW1lIjogImhhcHAtaG9tZSIsCiAgIkdsb2JhbFByb3h5IjogInRydWUiLAogICJVc2VDaHVua0ZpbGVzIjogInRydWUiLAogICJSZW1vdGVEbnMiOiAiOC44LjguOCIsCiAgIkRvbWVzdGljRG5zIjogIjc3Ljg4LjguOCIsCiAgIlJlbW90ZUROU1R5cGUiOiAiRG9IIiwKICAiUmVtb3RlRE5TRG9tYWluIjogImh0dHBzOi8vOC44LjguOC9kbnMtcXVlcnkiLAogICJSZW1vdGVETlNJUCI6ICI4LjguOC44IiwKICAiRG9tZXN0aWNETlNUeXBlIjogIkRvSCIsCiAgIkRvbWVzdGljRE5TRG9tYWluIjogImh0dHBzOi8vNzcuODguOC44L2Rucy1xdWVyeSIsCiAgIkRvbWVzdGljRE5TSVAiOiAiNzcuODguOC44IiwKICAiR2VvaXB1cmwiOiAiaHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L2doL2h5ZHJhcG9uaXF1ZS9yb3Njb212cG4tZ2VvaXBAMjAyNjExMTAxMTA0L3JlbGVhc2UvZ2VvaXAuZGF0IiwKICAiR2Vvc2l0ZXVybCI6ICJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvZ2gvaHlkcmFwb25pcXVlL3Jvc2NvbXZwbi1nZW9zaXRlQDIwMjYxMDEyMDk0OC9yZWxlYXNlL2dlb3NpdGUuZGF0IiwKICAiTGFzdFVwZGF0ZWQiOiAiMTc5NDMwODcxOCIsCiAgIlJvdXRlT3JkZXIiOiAiYmxvY2stZGlyZWN0LXByb3h5IiwKICAiRGlyZWN0U2l0ZXMiOiBbCiAgICAiZ2Vvc2l0ZTpwcml2YXRlIiwKICAgICJnZW9zaXRlOmNhdGVnb3J5LXJ1IiwKICAgICJnZW9zaXRlOndoaXRlbGlzdCIsCiAgICAiZ2Vvc2l0ZTptaWNyb3NvZnQiLAogICAgImdlb3NpdGU6YXBwbGUiLAogICAgImdlb3NpdGU6ZXBpY2dhbWVzIiwKICAgICJnZW9zaXRlOnJpb3QiLAogICAgImdlb3NpdGU6ZXNjYXBlZnJvbXRhcmtvdiIsCiAgICAiZ2Vvc2l0ZTpzdGVhbSIsCiAgICAiZ2Vvc2l0ZTp0d2l0Y2giLAogICAgImdlb3NpdGU6cGludGVyZXN0IiwKICAgICJnZW9zaXRlOmZhY2VpdCIsCiAgICAiZ2Vvc2l0ZTp5b3V0dWJlIgogIF0sCiAgIkRpcmVjdElwIjogWwogICAgImdlb2lwOnByaXZhdGUiLAogICAgImdlb2lwOmRpcmVjdCIKICBdLAogICJQcm94eVNpdGVzIjogWwogICAgImdlb3NpdGU6Z29vZ2xlLXBsYXkiLAogICAgImdlb3NpdGU6Z2l0aHViIiwKICAgICJnZW9zaXRlOnR3aXRjaC1hZHMiLAogICAgImdlb3NpdGU6dGVsZWdyYW0iCiAgXSwKICAiUHJveHlJcCI6IFtdLAogICJCbG9ja1NpdGVzIjogWwogICAgImdlb3NpdGU6d2luLXNweSIsCiAgICAiZ2Vvc2l0ZTp0b3JyZW50IiwKICAgICJnZW9zaXRlOmNhdGVnb3J5LWFkcyIKICBdLAogICJCbG9ja0lwIjogW10sCiAgIkRvbWFpblN0cmF0ZWd5IjogIklQSWZOb25NYXRjaCIsCiAgIkZha2VETlMiOiAiZmFsc2UiCn0=
```

**Общий режим** — `happ/happ-general.json`:

```
happ://routing/onadd/ewogICJOYW1lIjogImhhcHAtZ2VuZXJhbCIsCiAgIkdsb2JhbFByb3h5IjogInRydWUiLAogICJVc2VDaHVua0ZpbGVzIjogInRydWUiLAogICJSZW1vdGVEbnMiOiAiOC44LjguOCIsCiAgIkRvbWVzdGljRG5zIjogIjc3Ljg4LjguOCIsCiAgIlJlbW90ZUROU1R5cGUiOiAiRG9IIiwKICAiUmVtb3RlRE5TRG9tYWluIjogImh0dHBzOi8vOC44LjguOC9kbnMtcXVlcnkiLAogICJSZW1vdGVETlNJUCI6ICI4LjguOC44IiwKICAiRG9tZXN0aWNETlNUeXBlIjogIkRvSCIsCiAgIkRvbWVzdGljRE5TRG9tYWluIjogImh0dHBzOi8vNzcuODguOC44L2Rucy1xdWVyeSIsCiAgIkRvbWVzdGljRE5TSVAiOiAiNzcuODguOC44IiwKICAiR2VvaXB1cmwiOiAiaHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L2doL2h5ZHJhcG9uaXF1ZS9yb3Njb212cG4tZ2VvaXBAMjAyNjExMTAxMTA0L3JlbGVhc2UvZ2VvaXAuZGF0IiwKICAiR2Vvc2l0ZXVybCI6ICJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvZ2gvaHlkcmFwb25pcXVlL3Jvc2NvbXZwbi1nZW9zaXRlQDIwMjYxMDEyMDk0OC9yZWxlYXNlL2dlb3NpdGUuZGF0IiwKICAiTGFzdFVwZGF0ZWQiOiAiMTc5NDMwODcxOCIsCiAgIlJvdXRlT3JkZXIiOiAiYmxvY2stcHJveHktZGlyZWN0IiwKICAiRGlyZWN0U2l0ZXMiOiBbCiAgICAiZ2Vvc2l0ZTpwcml2YXRlIiwKICAgICJnZW9zaXRlOmNhdGVnb3J5LXJ1IiwKICAgICJnZW9zaXRlOndoaXRlbGlzdCIsCiAgICAiZ2Vvc2l0ZTptaWNyb3NvZnQiLAogICAgImdlb3NpdGU6YXBwbGUiLAogICAgImdlb3NpdGU6ZXBpY2dhbWVzIiwKICAgICJnZW9zaXRlOnJpb3QiLAogICAgImdlb3NpdGU6ZXNjYXBlZnJvbXRhcmtvdiIsCiAgICAiZ2Vvc2l0ZTpzdGVhbSIsCiAgICAiZ2Vvc2l0ZTp0d2l0Y2giLAogICAgImdlb3NpdGU6cGludGVyZXN0IiwKICAgICJnZW9zaXRlOmZhY2VpdCIKICBdLAogICJEaXJlY3RJcCI6IFsKICAgICJnZW9pcDpwcml2YXRlIiwKICAgICJnZW9pcDpkaXJlY3QiCiAgXSwKICAiUHJveHlTaXRlcyI6IFsKICAgICJnZW9zaXRlOmdvb2dsZS1wbGF5IiwKICAgICJnZW9zaXRlOmdpdGh1YiIsCiAgICAiZ2Vvc2l0ZTp0d2l0Y2gtYWRzIiwKICAgICJnZW9zaXRlOnRlbGVncmFtIiwKICAgICJnZW9zaXRlOnlvdXR1YmUiCiAgXSwKICAiUHJveHlJcCI6IFtdLAogICJCbG9ja1NpdGVzIjogWwogICAgImdlb3NpdGU6d2luLXNweSIsCiAgICAiZ2Vvc2l0ZTp0b3JyZW50IiwKICAgICJnZW9zaXRlOmNhdGVnb3J5LWFkcyIKICBdLAogICJCbG9ja0lwIjogW10sCiAgIkRvbWFpblN0cmF0ZWd5IjogIklQSWZOb25NYXRjaCIsCiAgIkZha2VETlMiOiAiZmFsc2UiCn0=
```

### Чем Happ-профили отличаются от Shadowrocket

- В обоих профилях `GlobalProxy: "true"`, поэтому всё, что не попало ни в один
  список, идёт через прокси. В `shadowrocket_home.conf` fallback —
  `FINAL,DIRECT`, то есть домашний режим Happ проксирует неописанный трафик.
- AI-сервисы в Happ отдельно не перечислены: в базе `roscomvpn-geosite` нет
  тегов `openai`, `anthropic` и подобных. Они проксируются за счёт
  `GlobalProxy`.
- Тега `geosite:instagram` в базе нет, поэтому Instagram в обоих профилях
  идёт по fallback (через прокси), хотя в домашнем режиме Shadowrocket он
  направляется напрямую.
- Правила Happ строятся на geosite/geoip-тегах, а не на списках `rules/*.list`.
- DNS: удалённый — Google DoH (`8.8.8.8`), локальный — Yandex DoH
  (`77.88.8.8`).

Подробности о категориях, политиках, порядке проверки и ограничениях —
в [CLAUDE.md](CLAUDE.md).
