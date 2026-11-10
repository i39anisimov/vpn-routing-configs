#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Проверка конфигов Shadowrocket и списков правил проекта vpn-routing-configs.

Что проверяется
---------------
1. rules/*.list:
   - синтаксис правил (DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, GEOIP, DST-PORT ...);
   - корректность доменов, IP/CIDR, ASN и портов;
   - отсутствие политик (DIRECT/PROXY) внутри списков — политику задаёт конфиг;
   - дубликаты внутри файла и конфликты между категориями;
   - обязательные заголовки (# NAME, # SOURCE, # TOTAL и т.д.);
   - кодировка UTF-8, LF, завершающий перевод строки.
2. ivn_home.conf / ivn_general.conf:
   - структура секций [General], [Proxy Group], [Rule];
   - известные ключи, булевы значения, DNS/маршруты;
   - корректность правил, политик и proxy-групп;
   - ровно одно правило FINAL,DIRECT, и оно последнее;
   - встроенный блок правил совпадает с rules/*.list и ожидаемыми политиками.

Использование
-------------
    python3 scripts/validate.py          # только проверка
    python3 scripts/validate.py --write  # проверить и пересобрать блоки правил
    python3 scripts/validate.py --strict # предупреждения считать ошибками

Код возврата: 0 — всё корректно, 1 — есть ошибки, 2 — ошибка запуска/файлов.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"

BEGIN_MARK = "# >>> GENERATED RULES: BEGIN >>>"
END_MARK = "# >>> GENERATED RULES: END <<<"

CONFIG_NAMES = ("ivn_home.conf", "ivn_general.conf")
REPO_FILE = ROOT / "repo.json"


@dataclass(frozen=True)
class RepoInfo:
    owner: str
    repo: str
    branch: str

    @property
    def raw_base(self) -> str:
        return (f"https://raw.githubusercontent.com/{self.owner}/"
                f"{self.repo}/{self.branch}")

    @property
    def rules_base(self) -> str:
        return f"{self.raw_base}/rules"


def load_repo_info(rep: Reporter) -> RepoInfo | None:
    if not REPO_FILE.exists():
        rep.error(REPO_FILE, None,
                  "не найден repo.json; укажите owner, repo и branch, "
                  "например: {\"owner\": \"ivan\", \"repo\": "
                  "\"vpn-routing-configs\", \"branch\": \"main\"}")
        return None
    try:
        data = json.loads(REPO_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        rep.error(REPO_FILE, None, f"не удалось прочитать repo.json: {exc}")
        return None
    owner = str(data.get("owner", "")).strip()
    repo = str(data.get("repo", "")).strip()
    branch = str(data.get("branch", "main")).strip() or "main"
    ok = True
    if not re.match(r"^[A-Za-z0-9_.-]+$", owner):
        rep.error(REPO_FILE, None, f"некорректный owner в repo.json: {owner!r}")
        ok = False
    if not re.match(r"^[A-Za-z0-9_.-]+$", repo):
        rep.error(REPO_FILE, None, f"некорректный repo в repo.json: {repo!r}")
        ok = False
    if not re.match(r"^[A-Za-z0-9_./-]+$", branch):
        rep.error(REPO_FILE, None, f"некорректный branch в repo.json: {branch!r}")
        ok = False
    if not ok:
        return None
    return RepoInfo(owner, repo, branch)


@dataclass(frozen=True)
class Category:
    key: str
    number: int
    title: str
    filename: str

    @property
    def path(self) -> Path:
        return RULES_DIR / self.filename


CATEGORIES = (
    Category("ru", 1, "RU-адреса", "ru.list"),
    Category("ai", 2, "AI", "ai.list"),
    Category("telegram", 3, "Telegram", "telegram.list"),
    Category("youtube", 4, "YouTube", "youtube.list"),
)

# Ожидаемые политики: что и куда должно ходить в каждом конфиге.
EXPECTED_POLICIES = {
    "ivn_home.conf": {
        "ru": "DIRECT",
        "ai": "PROXY",
        "telegram": "PROXY",
        "youtube": "DIRECT",
    },
    "ivn_general.conf": {
        "ru": "DIRECT",
        "ai": "PROXY",
        "telegram": "PROXY",
        "youtube": "PROXY",
    },
}

BUILTIN_POLICIES = {"DIRECT", "PROXY", "REJECT", "REJECT-DROP"}

# Политика FINAL для каждого конфига: home — всё остальное напрямую,
# general — всё остальное через прокси.
EXPECTED_FINAL = {
    "ivn_home.conf": "DIRECT",
    "ivn_general.conf": "PROXY",
}

# Типы правил, допустимые в файлах правил (политику задаёт конфиг).
LIST_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "GEOIP",
    "DST-PORT",
    "SRC-PORT",
    "PROCESS-NAME",
    "USER-AGENT",
    "URL-REGEX",
    "DOMAIN-REGEX",
}
IP_RULE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
PORT_RULE_TYPES = {"DST-PORT", "SRC-PORT"}
REGEX_RULE_TYPES = {"URL-REGEX", "DOMAIN-REGEX"}

ALLOWED_TLDS = {"ru", "su", "рф", "xn--p1ai", "youtube"}
# Широкие домены, которые осознанно входят в YouTube-категорию.
# AI-правила идут раньше YouTube, поэтому конкретные AI-домены выигрывают.
INTENTIONAL_BROAD_DOMAINS = {"googleapis.com", "googleusercontent.com", "gstatic.com"}
# Публичные суффиксы, которые почти наверняка означают ошибку в DOMAIN-SUFFIX.
PUBLIC_SUFFIXES = {
    "com", "net", "org", "io", "ai", "co", "me", "info", "biz", "app",
    "dev", "xyz", "tv", "cc", "cn", "uk", "de", "fr", "jp", "kr", "in",
    "br", "site", "online", "shop", "store", "cloud", "tech", "pro",
    "top", "link", "live", "media", "news", "gov", "edu", "email",
}

KNOWN_GENERAL_KEYS = {
    "ipv6", "prefer-ipv6", "private-ip-answer", "dns-direct-system",
    "dns-fallback-system", "dns-direct-fallback-proxy", "dns-server",
    "fallback-dns-server", "hijack-dns", "skip-proxy", "tun-excluded-routes",
    "tun-included-routes", "always-real-ip", "icmp-auto-reply",
    "always-reject-url-rewrite", "udp-policy-not-supported-behaviour",
    "include", "update-url", "bypass-system", "geoip-maxmind-url",
    "asn-maxmind-url", "geoip-maxmind-url6", "dns-server-fallback",
}
BOOL_KEYS = {
    "ipv6", "prefer-ipv6", "private-ip-answer", "dns-direct-system",
    "dns-fallback-system", "dns-direct-fallback-proxy", "icmp-auto-reply",
    "always-reject-url-rewrite", "bypass-system",
}
ALLOWED_SECTIONS = {
    "General", "Proxy", "Proxy Group", "Rule", "Host", "URL Rewrite",
    "Header", "Body Rewrite", "Script", "MITM", "Replica", "Panel", "Task",
}
GROUP_TYPES = {"url-test", "fallback", "select", "load-balance", "random"}
GROUP_PARAMS = {
    "url", "interval", "timeout", "tolerance", "policy-regex-filter",
    "policy-priority", "policy-path", "update-interval", "hidden", "no-alert",
    "interval", "alive", "expected-status",
}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
KEYWORD_RE = re.compile(r"^[a-z0-9._-]{2,63}$")
GEOIP_RE = re.compile(r"^[A-Z]{2}$")
PORT_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")
ASN_RE = re.compile(r"^\d{1,10}$")


@dataclass
class Diagnostic:
    level: str  # "error" | "warning"
    path: Path | None
    line: int | None
    message: str

    def format(self) -> str:
        prefix = "ERROR" if self.level == "error" else "WARN "
        where = ""
        if self.path is not None:
            try:
                shown = self.path.relative_to(ROOT)
            except ValueError:
                shown = self.path
            where = f" {shown}"
            if self.line is not None:
                where += f":{self.line}"
        return f"{prefix}{where}: {self.message}"


@dataclass
class Reporter:
    items: list[Diagnostic] = field(default_factory=list)

    def error(self, path, line, message):
        self.items.append(Diagnostic("error", path, line, message))

    def warning(self, path, line, message):
        self.items.append(Diagnostic("warning", path, line, message))

    @property
    def errors(self) -> int:
        return sum(1 for d in self.items if d.level == "error")

    @property
    def warnings(self) -> int:
        return sum(1 for d in self.items if d.level == "warning")

    def print(self):
        for d in self.items:
            print(d.format())


@dataclass
class Rule:
    type: str
    value: str
    modifiers: list[str]
    line: int
    raw: str

    @property
    def key(self):
        return (self.type, self.value.lower())

    def render(self, policy: str) -> str:
        parts = [self.type, self.value]
        if self.type in IP_RULE_TYPES:
            parts.append(policy)
            parts.extend(self.modifiers)
        else:
            parts.append(policy)
        return ",".join(parts)


def read_text(path: Path, rep: Reporter) -> str | None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        rep.error(path, None, f"не удалось прочитать файл: {exc}")
        return None
    if data.startswith(b"\xef\xbb\xbf"):
        rep.error(path, 1, "файл начинается с BOM; сохраните его в UTF-8 без BOM")
        data = data[3:]
    if b"\r" in data:
        rep.error(path, None, "найден CRLF; используйте переводы строк LF")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        rep.error(path, None, f"файл не является корректным UTF-8: {exc}")
        return None
    if text and not text.endswith("\n"):
        rep.error(path, None, "в конце файла нет перевода строки")
    return text


def check_domain(value: str, path: Path, line: int, rep: Reporter,
                 suffix: bool) -> bool:
    ok = True
    if value != value.lower():
        rep.error(path, line, f"домен должен быть в нижнем регистре: {value!r}")
        ok = False
    if value.startswith("."):
        rep.error(path, line, f"домен не должен начинаться с точки: {value!r}")
        return False
    if any(ch in value for ch in "*/: ?#"):
        rep.error(path, line, f"недопустимый символ в домене: {value!r}")
        return False

    ascii_value = value
    if any(ord(ch) > 127 for ch in value):
        try:
            ascii_value = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            rep.error(path, line, f"некорректный IDN-домен {value!r}: {exc}")
            return False
        rep.warning(path, line, "IDN-домен лучше хранить в punycode (xn--...): "
                                f"{value!r} -> {ascii_value!r}")

    labels = ascii_value.split(".")
    for label in labels:
        if not LABEL_RE.match(label):
            rep.error(path, line, f"некорректная метка домена: {label!r}")
            return False

    if suffix:
        if len(labels) == 1:
            if ascii_value not in ALLOWED_TLDS:
                rep.error(
                    path, line,
                    f"DOMAIN-SUFFIX из одного сегмента запрещён: {value!r} "
                    f"(разрешены только {', '.join(sorted(ALLOWED_TLDS))})",
                )
                return False
        if ascii_value in PUBLIC_SUFFIXES and ascii_value not in ALLOWED_TLDS:
            rep.error(path, line,
                      f"слишком широкий DOMAIN-SUFFIX — это публичный суффикс: "
                      f"{value!r}")
            return False
    else:
        if len(labels) < 2:
            rep.error(path, line, f"DOMAIN должен содержать минимум две метки: "
                                  f"{value!r}")
            return False
    return ok


def check_value(rule: Rule, path: Path, rep: Reporter):
    value = rule.value
    t = rule.type
    line = rule.line

    if not value:
        rep.error(path, line, "пустое значение правила")
        return

    if t in ("DOMAIN", "DOMAIN-SUFFIX"):
        check_domain(value, path, line, rep, suffix=(t == "DOMAIN-SUFFIX"))
    elif t == "DOMAIN-KEYWORD":
        if value != value.lower():
            rep.error(path, line, f"ключевое слово должно быть в нижнем регистре: "
                                  f"{value!r}")
        if not KEYWORD_RE.match(value):
            rep.error(path, line,
                      f"некорректное DOMAIN-KEYWORD {value!r}: разрешены "
                      f"a-z, 0-9, точка, дефис, подчёркивание; длина 2–63")
        if value in PUBLIC_SUFFIXES:
            rep.error(path, line, f"слишком широкое ключевое слово: {value!r}")
    elif t in ("IP-CIDR", "IP-CIDR6"):
        try:
            net = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            rep.error(path, line, f"некорректный {t} {value!r}: {exc}")
            return
        if t == "IP-CIDR6" and net.version != 6:
            rep.error(path, line, f"IP-CIDR6 требует IPv6-адрес: {value!r}")
        # Shadowrocket принимает IPv6 и в IP-CIDR (так делает blackmatrix7),
        # поэтому это не считается ошибкой.
        if "no-resolve" not in rule.modifiers:
            rep.warning(path, line,
                        f"для {t} рекомендуется модификатор no-resolve: {value!r}")
    elif t == "IP-ASN":
        if not ASN_RE.match(value) or not (1 <= int(value) <= 4294967295):
            rep.error(path, line, f"некорректный номер ASN: {value!r}")
        if "no-resolve" not in rule.modifiers:
            rep.warning(path, line,
                        f"для IP-ASN рекомендуется модификатор no-resolve: {value!r}")
    elif t == "GEOIP":
        if not GEOIP_RE.match(value):
            rep.error(path, line,
                      f"некорректный код страны GEOIP: {value!r} (ожидается RU и т.п.)")
    elif t in PORT_RULE_TYPES:
        m = PORT_RE.match(value)
        if not m:
            rep.error(path, line, f"некорректный порт/диапазон: {value!r}")
            return
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else start
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            rep.error(path, line, f"порт вне диапазона 1–65535: {value!r}")
        if start > end:
            rep.error(path, line, f"начало диапазона больше конца: {value!r}")
    elif t in REGEX_RULE_TYPES:
        try:
            re.compile(value)
        except re.error as exc:
            rep.error(path, line, f"некорректное регулярное выражение: {exc}")
    elif t == "PROCESS-NAME":
        if not value.strip():
            rep.error(path, line, "пустое имя процесса")


def parse_list_rule(raw: str, line_no: int, path: Path, rep: Reporter) -> Rule | None:
    if "\t" in raw:
        rep.error(path, line_no, "табуляция в строке правила")
    if raw != raw.strip():
        rep.error(path, line_no, "пробелы в начале или конце строки правила")
    stripped = raw.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if "#" in stripped:
        rep.error(path, line_no,
                  "встроенный комментарий после правила не поддерживается; "
                  "вынесите его на отдельную строку")
        stripped = stripped.split("#", 1)[0].strip()

    parts = [p.strip() for p in stripped.split(",")]
    if any(p == "" for p in parts):
        rep.error(path, line_no, "пустое поле в правиле (лишняя запятая?)")
        return None

    rule_type = parts[0].upper()
    if rule_type not in LIST_RULE_TYPES:
        rep.error(path, line_no,
                  f"неизвестный тип правила {parts[0]!r}; политика в .list "
                  f"запрещена, допустимые типы: {', '.join(sorted(LIST_RULE_TYPES))}")
        return None

    if rule_type in IP_RULE_TYPES:
        if len(parts) < 2:
            rep.error(path, line_no, "не хватает значения правила")
            return None
        modifiers = [p.lower() for p in parts[2:]]
        for mod in modifiers:
            if mod in BUILTIN_POLICIES or mod in ("AUTO", "PROXY"):
                rep.error(path, line_no,
                          f"политика {mod!r} не должна указываться в .list; "
                          f"её задаёт конфиг")
            elif mod != "no-resolve":
                rep.error(path, line_no, f"неизвестный модификатор правила: {mod!r}")
        rule = Rule(rule_type, parts[1], modifiers, line_no, stripped)
    else:
        if len(parts) != 2:
            rep.error(path, line_no,
                      f"для {rule_type} ожидается ровно два поля: "
                      f"{rule_type},<значение> (политика задаётся конфигом)")
            return None
        rule = Rule(rule_type, parts[1], [], line_no, stripped)

    check_value(rule, path, rep)
    return rule


@dataclass
class ParsedList:
    category: Category
    rules: list[Rule]
    header: list[str]


def parse_list(category: Category, rep: Reporter,
               fix_metadata: bool = False) -> ParsedList | None:
    path = category.path
    if not path.exists():
        rep.error(path, None, "файл правил не найден")
        return None
    text = read_text(path, rep)
    if text is None:
        return None

    rules: list[Rule] = []
    header: list[str] = []
    header_done = False
    for i, raw in enumerate(text.splitlines(), 1):
        rule = parse_list_rule(raw, i, path, rep)
        if rule is None:
            if raw.strip().startswith("#") and not header_done:
                header.append(raw.strip())
            if raw.strip() and not raw.strip().startswith("#"):
                header_done = True
            continue
        header_done = True
        rules.append(rule)

    if not any(h.startswith("# NAME:") for h in header):
        rep.error(path, 1, "отсутствует заголовок '# NAME:'")
    if not any(h.startswith("# SOURCE:") for h in header):
        rep.error(path, 1, "отсутствует заголовок '# SOURCE:'")
    if not any(h.startswith("# UPDATED:") for h in header):
        rep.warning(path, 1, "отсутствует заголовок '# UPDATED:'")
    if not any(h.startswith("# CATEGORY:") for h in header):
        rep.warning(path, 1, "отсутствует заголовок '# CATEGORY:'")
    else:
        cat_line = next(h for h in header if h.startswith("# CATEGORY:"))
        declared = cat_line.split(":", 1)[1].strip()
        if declared != category.key:
            rep.error(path, 1,
                      f"# CATEGORY: {declared!r} не совпадает с категорией "
                      f"{category.key!r}")
    total_line = next((h for h in header if h.startswith("# TOTAL:")), None)
    if total_line:
        try:
            declared_total = int(total_line.split(":", 1)[1].strip())
        except ValueError:
            rep.error(path, 1, f"некорректный # TOTAL: {total_line!r}")
        else:
            if declared_total != len(rules) and not fix_metadata:
                rep.warning(path, 1,
                            f"# TOTAL: {declared_total}, а фактически правил "
                            f"{len(rules)}; запустите --write, чтобы обновить "
                            f"заголовок")
    elif not fix_metadata:
        rep.warning(path, 1, "отсутствует заголовок '# TOTAL:'")

    return ParsedList(category, rules, header)


def check_duplicates(lists: dict[str, ParsedList], rep: Reporter):
    seen: dict[tuple, tuple[str, Rule, Path]] = {}
    for cat in CATEGORIES:
        parsed = lists.get(cat.key)
        if not parsed:
            continue
        for rule in parsed.rules:
            key = rule.key
            if key in seen:
                prev_cat, prev_rule, prev_path = seen[key]
                if prev_cat == cat.key:
                    rep.error(cat.path, rule.line,
                              f"дубликат правила {rule.raw!r}; первое "
                              f"вхождение — строка {prev_rule.line}")
                else:
                    rep.error(cat.path, rule.line,
                              f"правило {rule.raw!r} уже есть в категории "
                              f"{prev_cat} ({prev_path.name}:{prev_rule.line}); "
                              f"одно правило не может быть в двух категориях")
            else:
                seen[key] = (cat.key, rule, cat.path)

    # Пересечения по вложенности доменов и ключевым словам — предупреждения.
    suffixes = []
    keywords = []
    for cat in CATEGORIES:
        parsed = lists.get(cat.key)
        if not parsed:
            continue
        for rule in parsed.rules:
            if rule.type == "DOMAIN-SUFFIX":
                suffixes.append((cat, rule))
            elif rule.type == "DOMAIN-KEYWORD":
                keywords.append((cat, rule))

    for i, (cat_a, rule_a) in enumerate(suffixes):
        for cat_b, rule_b in suffixes[i + 1:]:
            if cat_a.key == cat_b.key:
                continue
            a, b = rule_a.value, rule_b.value
            if a in ALLOWED_TLDS or b in ALLOWED_TLDS:
                continue
            if a in INTENTIONAL_BROAD_DOMAINS or b in INTENTIONAL_BROAD_DOMAINS:
                continue
            if b.endswith("." + a) or a.endswith("." + b):
                rep.warning(
                    cat_b.path, rule_b.line,
                    f"домен {b!r} пересекается с {a!r} из категории "
                    f"{cat_a.key} ({cat_a.filename}:{rule_a.line}); "
                    f"порядок правил в конфиге определит победителя",
                )

    for cat_k, rule_k in keywords:
        keyword = rule_k.value
        for cat_s, rule_s in suffixes:
            if cat_k.key == cat_s.key:
                continue
            if keyword in rule_s.value:
                rep.warning(
                    cat_s.path, rule_s.line,
                    f"домен {rule_s.value!r} содержит ключевое слово "
                    f"{keyword!r} из категории {cat_k.key} "
                    f"({cat_k.filename}:{rule_k.line})",
                )


# --------------------------------------------------------------------------
# Конфиги
# --------------------------------------------------------------------------

@dataclass
class Section:
    name: str
    line: int
    lines: list[tuple[int, str]] = field(default_factory=list)


def split_sections(text: str, path: Path, rep: Reporter) -> list[Section]:
    sections: list[Section] = []
    current: Section | None = None
    for i, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            name = stripped[1:-1].strip()
            current = Section(name, i)
            sections.append(current)
            continue
        if current is None:
            if stripped and not stripped.startswith("#"):
                rep.error(path, i, "содержимое до первой секции")
            continue
        current.lines.append((i, raw))
    return sections


def parse_rule_line(raw: str, line_no: int, path: Path, rep: Reporter,
                    groups: set[str]) -> Rule | None:
    stripped = raw.strip()
    if stripped.startswith("#") or not stripped:
        return None
    if "\t" in raw:
        rep.error(path, line_no, "табуляция в строке правила")
    if raw != raw.strip():
        rep.error(path, line_no, "пробелы в начале или конце строки правила")
    if "#" in stripped:
        rep.error(path, line_no, "встроенный комментарий после правила")
        stripped = stripped.split("#", 1)[0].strip()

    parts = [p.strip() for p in stripped.split(",")]
    if any(p == "" for p in parts):
        rep.error(path, line_no, "пустое поле в правиле (лишняя запятая?)")
        return None

    rule_type = parts[0].upper()
    allowed_types = LIST_RULE_TYPES | {"FINAL", "RULE-SET", "DOMAIN-SET"}
    if rule_type not in allowed_types:
        rep.error(path, line_no, f"неизвестный тип правила {parts[0]!r}")
        return None

    if rule_type == "FINAL":
        if len(parts) != 2:
            rep.error(path, line_no, "FINAL должен иметь вид FINAL,<политика>")
            return None
        policy = parts[1].upper()
        if policy not in BUILTIN_POLICIES:
            rep.error(path, line_no, f"недопустимая политика FINAL: {parts[1]!r}")
        return Rule(rule_type, "", [], line_no, stripped)

    if rule_type in ("RULE-SET", "DOMAIN-SET"):
        if len(parts) < 3:
            rep.error(path, line_no,
                      f"{rule_type} должен иметь вид {rule_type},<url>,<политика>")
            return None
        if not re.match(r"^https?://", parts[1]):
            rep.error(path, line_no,
                      f"{rule_type}: ожидается http(s)-URL, получено {parts[1]!r}")
        policy = parts[2].upper()
        if policy not in BUILTIN_POLICIES and parts[2] not in groups:
            rep.error(path, line_no, f"недопустимая политика: {parts[2]!r}")
        return Rule(rule_type, parts[1], parts[3:], line_no, stripped)

    def is_policy(token: str) -> bool:
        return token.upper() in BUILTIN_POLICIES or token in groups

    if rule_type in IP_RULE_TYPES:
        if len(parts) < 3:
            rep.error(path, line_no,
                      f"для {rule_type} нужна политика: {rule_type},<значение>,<политика>")
            return None
        policy_idx = None
        for idx in range(2, len(parts)):
            if is_policy(parts[idx]):
                policy_idx = idx
                break
        if policy_idx is None:
            rep.error(path, line_no,
                      f"не найдена политика в правиле: {stripped!r}")
            return None
        modifiers = [p.lower() for p in parts[2:] if p != parts[policy_idx]]
        for mod in modifiers:
            if mod != "no-resolve":
                rep.error(path, line_no, f"неизвестный модификатор: {mod!r}")
        rule = Rule(rule_type, parts[1], modifiers, line_no, stripped)
        check_value(rule, path, rep)
        return rule

    if len(parts) != 3:
        rep.error(path, line_no,
                  f"для {rule_type} ожидается {rule_type},<значение>,<политика>")
        return None
    policy = parts[2]
    if not is_policy(policy):
        rep.error(path, line_no,
                  f"недопустимая политика {policy!r}; допустимые: "
                  f"{', '.join(sorted(BUILTIN_POLICIES))} и группы "
                  f"{', '.join(sorted(groups)) or '(нет)'}")
    rule = Rule(rule_type, parts[1], [], line_no, stripped)
    check_value(rule, path, rep)
    return rule


def parse_general(section: Section, path: Path, rep: Reporter) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_no, raw in section.lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.*)$", stripped)
        if not m:
            rep.error(path, line_no,
                      "строка в [General] должна иметь вид 'ключ = значение'")
            continue
        key = m.group(1).lower()
        value = m.group(2).strip()
        if key in values:
            rep.error(path, line_no, f"дубликат ключа {key!r} в [General]")
        values[key] = value
        if key not in KNOWN_GENERAL_KEYS:
            rep.warning(path, line_no, f"неизвестный ключ [General]: {key!r}")
        if key in BOOL_KEYS and value.lower() not in ("true", "false"):
            rep.error(path, line_no,
                      f"{key} должно быть true или false, получено {value!r}")
        if key == "udp-policy-not-supported-behaviour" and \
                value.upper() not in ("REJECT", "DIRECT", "PROXY"):
            rep.error(path, line_no,
                      f"udp-policy-not-supported-behaviour: недопустимое "
                      f"значение {value!r}")
        if key == "include":
            inc = ROOT / value
            if not inc.exists():
                rep.error(path, line_no, f"include указывает на отсутствующий файл: {value!r}")
        if key == "update-url" and not re.match(r"^https?://", value):
            rep.error(path, line_no, f"update-url должен быть http(s)-URL: {value!r}")
        if key in ("skip-proxy", "tun-excluded-routes", "tun-included-routes",
                   "always-real-ip"):
            for item in [x.strip() for x in value.split(",") if x.strip()]:
                if "/" in item and not item.startswith("*"):
                    try:
                        ipaddress.ip_network(item, strict=False)
                    except ValueError:
                        rep.error(path, line_no,
                                  f"{key}: некорректный CIDR {item!r}")
    return values


def parse_proxy_groups(section: Section, path: Path, rep: Reporter) -> set[str]:
    groups: set[str] = set()
    for line_no, raw in section.lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"^([^=]+?)\s*=\s*(.*)$", stripped)
        if not m:
            rep.error(path, line_no,
                      "строка в [Proxy Group] должна иметь вид 'имя = тип, ...'")
            continue
        name = m.group(1).strip()
        body = m.group(2).strip()
        if not name:
            rep.error(path, line_no, "пустое имя proxy-группы")
            continue
        if name.upper() in BUILTIN_POLICIES:
            rep.error(path, line_no,
                      f"имя группы {name!r} конфликтует со встроенной политикой")
        if name in groups:
            rep.error(path, line_no, f"дубликат proxy-группы {name!r}")
        groups.add(name)
        parts = [p.strip() for p in body.split(",") if p.strip()]
        if not parts:
            rep.error(path, line_no, f"пустое описание группы {name!r}")
            continue
        if parts[0] not in GROUP_TYPES:
            rep.error(path, line_no,
                      f"неизвестный тип группы {parts[0]!r}; допустимые: "
                      f"{', '.join(sorted(GROUP_TYPES))}")
        for param in parts[1:]:
            if "=" not in param:
                rep.error(path, line_no,
                          f"параметр группы должен иметь вид key=value: {param!r}")
                continue
            key, value = param.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key not in GROUP_PARAMS:
                rep.warning(path, line_no,
                            f"неизвестный параметр proxy-группы {key!r}")
            if key in ("interval", "timeout", "tolerance") and not value.isdigit():
                rep.error(path, line_no, f"{key} должен быть числом: {value!r}")
            if key == "url" and not re.match(r"^https?://", value):
                rep.error(path, line_no, f"url группы должен быть http(s): {value!r}")
            if key == "policy-regex-filter":
                try:
                    re.compile(value)
                except re.error as exc:
                    rep.error(path, line_no,
                              f"некорректный policy-regex-filter: {exc}")
    return groups


def extract_block(section: Section, path: Path, rep: Reporter):
    begin_idx = end_idx = None
    for idx, (line_no, raw) in enumerate(section.lines):
        if raw.strip() == BEGIN_MARK:
            if begin_idx is not None:
                rep.error(path, line_no, "повторяющийся BEGIN-маркер блока правил")
            begin_idx = idx
        elif raw.strip() == END_MARK:
            if end_idx is not None:
                rep.error(path, line_no, "повторяющийся END-маркер блока правил")
            end_idx = idx
    if begin_idx is None or end_idx is None:
        rep.error(path, section.line,
                  f"не найдены маркеры блока правил:\n  {BEGIN_MARK}\n  {END_MARK}")
        return None, None
    if begin_idx > end_idx:
        rep.error(path, section.line, "BEGIN-маркер находится после END-маркера")
        return None, None
    return begin_idx, end_idx


def validate_config(path: Path, rep: Reporter, groups: set[str] | None = None,
                    check_sync: bool = True,
                    repo: RepoInfo | None = None) -> dict | None:
    if not path.exists():
        rep.error(path, None, "конфиг не найден")
        return None
    text = read_text(path, rep)
    if text is None:
        return None

    sections = split_sections(text, path, rep)
    names = [s.name for s in sections]
    for required in ("General", "Rule"):
        if names.count(required) != 1:
            rep.error(path, None,
                      f"секция [{required}] должна встречаться ровно один раз "
                      f"(найдено {names.count(required)})")
    if names.count("Proxy Group") > 1:
        rep.error(path, None, "секция [Proxy Group] встречается более одного раза")
    for name in names:
        if name not in ALLOWED_SECTIONS:
            rep.error(path, None, f"неизвестная секция [{name}]")
    if names and names[0] != "General":
        rep.error(path, sections[0].line, "первой должна идти секция [General]")
    if "Rule" in names and names[-1] != "Rule":
        rep.error(path, sections[-1].line, "секция [Rule] должна быть последней")

    result = {"path": path, "general": {}, "groups": set(), "rules": []}

    for section in sections:
        if section.name == "General":
            result["general"] = parse_general(section, path, rep)
        elif section.name == "Proxy Group":
            result["groups"] = parse_proxy_groups(section, path, rep)
            if groups is not None:
                groups.update(result["groups"])
        elif section.name == "Rule":
            local_groups = set(result["groups"]) | (groups or set())
            begin_idx, end_idx = extract_block(section, path, rep)
            if begin_idx is None:
                continue

            # Всё вне блока — только комментарии и один FINAL.
            outside = section.lines[:begin_idx] + section.lines[end_idx + 1:]
            finals = []
            for line_no, raw in outside:
                stripped = raw.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = [p.strip() for p in stripped.split(",")]
                if parts[0].upper() == "FINAL":
                    finals.append((line_no, stripped, parts))
                else:
                    rep.error(path, line_no,
                              f"правило вне блока rules/*.list: {stripped!r}; "
                              f"добавьте его в соответствующий файл (--write)")
            if len(finals) != 1:
                rep.error(path, section.line,
                          f"должно быть ровно одно правило FINAL (найдено {len(finals)})")
            else:
                fin_line, fin_raw, fin_parts = finals[0]
                expected_final = EXPECTED_FINAL.get(path.name, "DIRECT")
                if len(fin_parts) != 2 or fin_parts[1].upper() != expected_final:
                    rep.error(path, fin_line,
                              f"ожидается FINAL,{expected_final} для {path.name}")
                last_rule_line = max(
                    [ln for ln, raw in outside
                     if raw.strip() and not raw.strip().startswith("#")],
                    default=None,
                )
                if last_rule_line != fin_line:
                    rep.error(path, fin_line, "FINAL должен быть последним правилом")

            block: list[Rule] = []
            for line_no, raw in section.lines[begin_idx + 1:end_idx]:
                rule = parse_rule_line(raw, line_no, path, rep, local_groups)
                if rule is not None:
                    block.append(rule)
            result["rules"] = block

        elif section.name in ("Host", "URL Rewrite", "Header", "Body Rewrite",
                              "Script", "MITM", "Replica", "Panel", "Task"):
            # Эти секции не используются, но не запрещены.
            pass

    if check_sync:
        check_config_sync(path, result.get("rules", []), repo, rep)
        if repo is not None:
            expected_update_url = f"{repo.raw_base}/{path.name}"
            actual_update_url = result.get("general", {}).get("update-url")
            if actual_update_url is None:
                rep.warning(path, None,
                            "нет активного update-url; --write добавит ссылку "
                            f"на {expected_update_url}")
            elif actual_update_url != expected_update_url:
                rep.error(path, None,
                          f"update-url должен быть {expected_update_url!r}, "
                          f"найдено {actual_update_url!r}")
    return result


def render_block(config_name: str, repo: RepoInfo) -> str:
    policies = EXPECTED_POLICIES[config_name]
    lines = [BEGIN_MARK]
    for cat in CATEGORIES:
        policy = policies[cat.key]
        lines.append("")
        lines.append(f"# [{cat.number}/4] {cat.title} -> {policy}")
        lines.append(f"RULE-SET,{repo.rules_base}/{cat.filename},{policy}")
    lines.append("")
    lines.append(END_MARK)
    return "\n".join(lines)


def check_config_sync(path: Path, block: list[Rule], repo: RepoInfo | None,
                      rep: Reporter):
    config_name = path.name
    if config_name not in EXPECTED_POLICIES:
        return
    if repo is None:
        rep.error(path, None,
                  "не удалось проверить RULE-SET-ссылки: нет repo.json")
        return
    policies = EXPECTED_POLICIES[config_name]

    # Внутри блока допустимы только RULE-SET на rules/*.list.
    for rule in block:
        if rule.type != "RULE-SET":
            rep.error(path, rule.line,
                      f"внутри блока RULE-SET найдено правило {rule.raw!r}; "
                      f"списки правил должны подключаться только через RULE-SET")
            return

    expected = [
        f"RULE-SET,{repo.rules_base}/{cat.filename},{policies[cat.key]}"
        for cat in CATEGORIES
    ]
    actual = [rule.raw for rule in block]
    if len(actual) != len(expected):
        rep.error(path, None,
                  f"блок RULE-SET устарел: строк {len(actual)}, ожидается "
                  f"{len(expected)}; выполните "
                  f"'python3 scripts/validate.py --write'")
        return
    for idx, (want, got) in enumerate(zip(expected, actual), 1):
        if want != got:
            rep.error(path, None,
                      f"блок RULE-SET устарел на позиции {idx}: ожидается "
                      f"{want!r}, найдено {got!r}; выполните "
                      f"'python3 scripts/validate.py --write'")
            return


def replace_update_url(text: str, path: Path, repo: RepoInfo) -> str:
    expected = f"{repo.raw_base}/{path.name}"
    pattern = re.compile(r"(?m)^#?\s*update-url\s*=.*$")
    if pattern.search(text):
        return pattern.sub(f"update-url = {expected}", text, count=1)
    return text


def replace_block(text: str, block: str) -> tuple[str, bool]:
    pattern = re.compile(
        re.escape(BEGIN_MARK) + r".*?" + re.escape(END_MARK),
        re.DOTALL,
    )
    new_text, count = pattern.subn(block, text)
    return new_text, count == 1


def update_list_metadata(parsed: ParsedList) -> bool:
    """Обновляет # TOTAL: и # UPDATED: в заголовке списка. True, если файл изменён."""
    path = parsed.category.path
    text = path.read_text(encoding="utf-8")
    new_text = re.sub(r"(?m)^# TOTAL:.*$", f"# TOTAL: {len(parsed.rules)}", text,
                      count=1)
    new_text = re.sub(r"(?m)^# UPDATED:.*$",
                      f"# UPDATED: {datetime.date.today().isoformat()}",
                      new_text, count=1)
    if new_text == text:
        return False
    atomic_write(path, new_text)
    return True


def atomic_write(path: Path, text: str):
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Проверка и пересборка конфигов Shadowrocket",
    )
    parser.add_argument("--write", action="store_true",
                        help="пересобрать блоки правил в конфигах")
    parser.add_argument("--strict", action="store_true",
                        help="считать предупреждения ошибками")
    args = parser.parse_args(argv)

    rep = Reporter()

    if not RULES_DIR.is_dir():
        print(f"ERROR: каталог правил не найден: {RULES_DIR}", file=sys.stderr)
        return 2

    known_files = {c.filename for c in CATEGORIES}
    for path in sorted(RULES_DIR.glob("*.list")):
        if path.name not in known_files:
            rep.warning(path, None,
                        "файл не входит ни в одну категорию и не используется конфигами")

    parsed_lists: dict[str, ParsedList] = {}
    print("Проверка списков правил:")
    for cat in CATEGORIES:
        parsed = parse_list(cat, rep, fix_metadata=args.write)
        if parsed is not None:
            parsed_lists[cat.key] = parsed
            print(f"  rules/{cat.filename:<15} {len(parsed.rules):>5} правил")

    check_duplicates(parsed_lists, rep)
    repo = load_repo_info(rep)

    print("Проверка конфигов:")
    configs: dict[str, dict] = {}
    for name in CONFIG_NAMES:
        path = ROOT / name
        result = validate_config(path, rep, check_sync=False)
        if result is not None:
            configs[name] = result

    if rep.errors:
        print()
        rep.print()
        print(f"\nОшибок: {rep.errors}, предупреждений: {rep.warnings}")
        print("Запись отменена: сначала исправьте ошибки.")
        return 1

    # Сверка General / Proxy Group между конфигами.
    if len(configs) == len(CONFIG_NAMES):
        base_name = CONFIG_NAMES[0]
        base = configs[base_name]
        for name in CONFIG_NAMES[1:]:
            other = configs[name]
            # update-url у каждого конфига свой — это нормально.
            base_general = {k: v for k, v in base["general"].items()
                            if k != "update-url"}
            other_general = {k: v for k, v in other["general"].items()
                             if k != "update-url"}
            if base_general != other_general:
                rep.warning(ROOT / name, None,
                            f"секция [General] отличается от {base_name}")
            if base["groups"] != other["groups"]:
                rep.warning(ROOT / name, None,
                            f"[Proxy Group] отличается от {base_name}")

    if rep.items:
        print()
        rep.print()

    if args.write:
        # Проверяем, что все категории разобраны, затем пересобираем блоки.
        if len(parsed_lists) != len(CATEGORIES):
            rep.error(ROOT, None, "не все списки категорий удалось прочитать")
        elif repo is None:
            rep.error(REPO_FILE, None,
                      "запись отменена: сначала заполните repo.json")
        else:
            for parsed in parsed_lists.values():
                if update_list_metadata(parsed):
                    print(f"  обновлён заголовок rules/{parsed.category.filename}")
            for name in CONFIG_NAMES:
                path = ROOT / name
                if not path.exists():
                    rep.error(path, None, "конфиг не найден")
                    continue
                text = read_text(path, rep)
                if text is None:
                    continue
                block = render_block(name, repo)
                new_text, ok = replace_block(text, block)
                if not ok:
                    rep.error(path, None,
                              "не удалось заменить блок RULE-SET (маркеры "
                              "отсутствуют или задвоены)")
                    continue
                new_text = replace_update_url(new_text, path, repo)
                if new_text != text:
                    atomic_write(path, new_text)
                    print(f"  обновлён {name}")
                else:
                    print(f"  без изменений {name}")

    # Финальная проверка уже с синхронизацией блоков.
    final_rep = Reporter()
    print("Проверка синхронизации правил:")
    for name in CONFIG_NAMES:
        path = ROOT / name
        before = len(final_rep.items)
        validate_config(path, final_rep, check_sync=True, repo=repo)
        status = "OK" if len(final_rep.items) == before else "есть замечания"
        print(f"  {name:<18} {status}")

    if final_rep.items:
        print()
        final_rep.print()
    total_errors = rep.errors + final_rep.errors
    total_warnings = rep.warnings + final_rep.warnings
    print(f"\nОшибок: {total_errors}, предупреждений: {total_warnings}")

    if total_errors or (args.strict and total_warnings):
        if total_errors == 0 and args.strict:
            print("Режим --strict: предупреждения считаются ошибками.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
