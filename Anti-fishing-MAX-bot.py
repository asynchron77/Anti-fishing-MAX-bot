"""
Программный комплекс «АнтиФишинг | Защита чата»
Прототип для конкурса «Большие вызовы» (2026-2027 уч. год)
Назначение:
1. Взаимодействие с отечественным мессенджером MAX через REST API (https://platform-api2.max.ru)
2. Трехуровневый анализ входящих сообщений в чатах:
   - Модуль 1: Лексико-структурный и энтропийный анализатор URL-адресов (S_url)
   - Модуль 2: Семантико-эвристический детектор социальной инженерии (S_heur)
   - Модуль 3: Статистический ML-классификатор символьных n-грамм (TF-IDF + Наивный Байес, S_ml)
3. Работа в реальном времени (Long Polling) и автоматизированный стенд испытаний (N = 200).
"""

import os
import sys
import re
import math
import time
import json
import urllib.parse
from collections import Counter
from typing import List, Dict, Tuple

import requests
import urllib3
import numpy as np

MAX_BOT_TOKEN = os.getenv("MAX_BOT_TOKEN", "вставить токен бота")

# Шлюз platform-api2.max.ru использует сертификат Минцифры РФ, которого нет в стандартном Python certifi.
# Для быстрого локального запуска на Windows оставляем VERIFY_SSL = False (или установите pip-system-certs и поставьте True).
VERIFY_SSL = False
if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# 1. КЛИЕНТ ПЛАТФОРМЫ MAX BOT API (https://platform-api2.max.ru)


class MaxBotClient:
    """
    Клиент для взаимодействия с сервером MAX Bot API.
    Использует шлюз https://platform-api2.max.ru и заголовок Authorization.
    """
    BASE_URL = "https://platform-api2.max.ru"

    def __init__(self, access_token: str):
        self.access_token = access_token.strip()
        self.headers = {
            "Authorization": self.access_token,
            "Content-Type": "application/json"
        }

    def build_send_message_payload(self, text: str, notify: bool = True) -> dict:
        """
        Формирует JSON-тело запроса POST /messages (NewMessageBody) по спецификации MAX API:
        text, notify, format (параметр chat_id или user_id передается в query-строке URL).
        """
        return {
            "text": text,
            "notify": notify,
            "format": "markdown"
        }

    def send_message(self, chat_id: int = None, text: str = "", notify: bool = True, user_id: int = None) -> bool:
        """Отправляет сообщение в чат или пользователю MAX через POST /messages."""
        payload = self.build_send_message_payload(text=text, notify=notify)
        params = {"disable_link_preview": "true"}
        if chat_id is not None:
            params["chat_id"] = int(chat_id)
        elif user_id is not None:
            params["user_id"] = int(user_id)
        else:
            print("[!] Ошибка: не указан ни chat_id, ни user_id для отправки сообщения.")
            return False

        try:
            resp = requests.post(
                f"{self.BASE_URL}/messages",
                headers=self.headers,
                params=params,
                json=payload,
                verify=VERIFY_SSL,
                timeout=15
            )
            if not resp.ok:
                print(f"[!] Ошибка отправки сообщения ({resp.status_code}): {resp.text}")
                return False
            return True
        except Exception as e:
            print(f"[!] Сбой сети при отправке сообщения: {e}")
            return False

    def format_security_alert(self, analysis_result: dict) -> str:
        """Генерирует карточку результата проверки для отправки пользователю в чат MAX."""
        verdict = analysis_result["verdict"]
        score_pct = int(round(analysis_result["total_risk"] * 100))
        reasons = analysis_result["reasons"]

        if verdict == "DANGER":
            header = f"🚨 **[ВНИМАНИЕ: ВЫСОКИЙ РИСК УГРОЗЫ - R = {analysis_result['total_risk']:.2f} ({score_pct}%)]**"
            rec = "⛔ **Рекомендация:** Не переходите по ссылкам, не вводите пароли и никому не сообщайте коды из СМС!"
        elif verdict == "SUSPICIOUS":
            header = f"⚠️ **[ПОДОЗРИТЕЛЬНОЕ СООБЩЕНИЕ - РИСК R = {analysis_result['total_risk']:.2f} ({score_pct}%)]**"
            rec = "⚠️ **Рекомендация:** Будьте осторожны, перепроверьте информацию через официальные каналы."
        else:
            header = f"✅ **[ПРОВЕРКА ЗАВЕРШЕНА: БЕЗОПАСНО - R = {analysis_result['total_risk']:.2f} ({score_pct}%)]**"
            rec = "🛡 Признаков фишинга и социальной инженерии не обнаружено."

        lines = [
            header,
            "",
            "**Покомпонентный анализ модулей:**",
            f"• Модуль 1 (URL-анализатор): `S_url = {analysis_result['url_score']:.2f}`",
            f"• Модуль 2 (Детектор соц. инженерии): `S_heur = {analysis_result['heur_score']:.2f}`",
            f"• Модуль 3 (ML-классификатор n-грамм): `S_ml = {analysis_result['ml_score']:.2f}`",
            ""
        ]

        if reasons:
            lines.append("**Выявленные факторы риска:**")
            for r in reasons:
                lines.append(f"• {r}")
            lines.append("")

        lines.append(rec)
        lines.append(f"⏱ _Время анализа: {analysis_result['latency_ms']:.2f} мс_")
        return "\n".join(lines)

    @staticmethod
    def _extract_message_text(msg: dict) -> str:
        """Извлекает текст как из обычного, так и из пересланного сообщения."""
        body = msg.get("body") or {}
        parts = []
        if body.get("text"):
            parts.append(body["text"].strip())

        # Если сообщение переслано (forwarded), проверяем также вложенный текст
        link = msg.get("link") or {}
        linked_msg = link.get("message") or {}
        if isinstance(linked_msg, dict):
            linked_text = linked_msg.get("text") or (linked_msg.get("body") or {}).get("text")
            if linked_text and linked_text.strip() not in parts:
                parts.append(linked_text.strip())

        return "\n".join(parts).strip()

    def start_polling(self, engine):
        """Запускает основной цикл получения обновлений (GET /updates) в реальном времени."""
        if not self.access_token or self.access_token == "вставить токен бота":
            print("[!] ОШИБКА: Ты не вставил токен бота в переменную MAX_BOT_TOKEN в начале файла!")
            return

        # Проверяем подключение и токен через GET /me
        try:
            me_resp = requests.get(f"{self.BASE_URL}/me", headers=self.headers, verify=VERIFY_SSL, timeout=10)
            if me_resp.ok:
                bot_info = me_resp.json()
                bot_name = bot_info.get("first_name") or bot_info.get("name") or "АнтиФишинг | Защита чата"
                print(f"[+] Успешная авторизация в MAX API! Бот: {bot_name} (@{bot_info.get('username')})")
            else:
                print(f"[!] Предупреждение GET /me ({me_resp.status_code}): {me_resp.text}")
        except Exception as e:
            print(f"[!] Не удалось проверить профиль бота: {e}")

        marker = None
        print("[*] Ожидание сообщений (Long Polling запущен)... Нажми Ctrl+C для остановки.")

        while True:
            try:
                params = {"timeout": 25}
                if marker is not None:
                    params["marker"] = marker

                resp = requests.get(
                    f"{self.BASE_URL}/updates",
                    headers=self.headers,
                    params=params,
                    verify=VERIFY_SSL,
                    timeout=35
                )

                if not resp.ok:
                    print(f"[!] Ошибка получения обновлений ({resp.status_code}): {resp.text}")
                    time.sleep(3)
                    continue

                data = resp.json()
                if "marker" in data and data["marker"] is not None:
                    marker = data["marker"]

                for update in data.get("updates", []):
                    upd_type = update.get("update_type")

                    # Событие запуска бота кнопкой «Начать»
                    if upd_type == "bot_started":
                        chat_id = update.get("chat_id")
                        user_obj = update.get("user") or {}
                        user_id = user_obj.get("user_id")
                        welcome_text = (
                            "🛡 **Комплекс «АнтиФишинг | Защита чата» активен!**\n\n"
                            "Отправьте или перешлите сюда любое подозрительное сообщение или ссылку. "
                            "Бот проведет трехуровневую проверку:\n"
                            "1️⃣ Лексико-структурный и энтропийный анализ URL\n"
                            "2️⃣ Детектор психологических триггеров социальной инженерии\n"
                            "3️⃣ Статистический ML-классификатор символьных n-грамм"
                        )
                        self.send_message(chat_id=chat_id, text=welcome_text, user_id=user_id)
                        continue

                    # Событие нового сообщения в личном или групповом чате
                    if upd_type == "message_created":
                        msg = update.get("message") or {}
                        sender = msg.get("sender") or {}
                        if sender.get("is_bot"):
                            continue

                        recipient = msg.get("recipient") or {}
                        chat_id = recipient.get("chat_id")
                        chat_type = recipient.get("chat_type", "dialog")
                        sender_uid = sender.get("user_id")

                        text = self._extract_message_text(msg)
                        if not text or (chat_id is None and sender_uid is None):
                            continue

                        if text.lower() in ("/start", "/help", "старт", "помощь"):
                            help_text = (
                                "🛡 **Справка по работе бота «АнтиФишинг | Защита чата»:**\n"
                                "• В личном диалоге я проверяю **каждое** присланное или пересланное сообщение и выдаю полный отчет.\n"
                                "• В групповом чате я работаю в режиме тихого антифрод-фильтра и отправляю предупреждение только при обнаружении угрозы (`SUSPICIOUS` / `DANGER`)."
                            )
                            self.send_message(chat_id=chat_id, text=help_text, user_id=sender_uid)
                            continue

                        # Запускаем анализ сообщения
                        result = engine.analyze_message(text)
                        print(
                            f"[Анализ] Чат {chat_id} ({chat_type}) | "
                            f"Вердикт: {result['verdict']} (R={result['total_risk']:.2f}) | "
                            f"Время: {result['latency_ms']:.2f} мс"
                        )

                        # В личке отвечаем на все; в группе - только если сообщение подозрительное или опасное
                        if chat_type == "dialog" or result["verdict"] != "SAFE":
                            alert_card = self.format_security_alert(result)
                            self.send_message(chat_id=chat_id, text=alert_card, user_id=sender_uid)

            except KeyboardInterrupt:
                print("\n[*] Бот остановлен пользователем.")
                break
            except requests.exceptions.RequestException as e:
                print(f"[!] Сетевая ошибка: {e}. Переподключение через 3 сек...")
                time.sleep(3)
            except Exception as e:
                print(f"[!] Непредвиденная ошибка в цикле: {e}")
                time.sleep(2)


# 2. МОДУЛЬ АНАЛИЗА ССЫЛОК (URL PHISHING DETECTOR)


TRUSTED_DOMAINS = {
    "gosuslugi.ru", "sberbank.ru", "sber.ru", "tbank.ru", "tinkoff.ru",
    "vtb.ru", "cbr.ru", "nalog.gov.ru", "mos.ru", "max.ru", "vk.com", "vk.ru",
    "yandex.ru", "ya.ru", "mail.ru", "ozon.ru", "wildberries.ru", "avito.ru",
    "pochta.ru", "rzd.ru", "edu.gov.ru", "sirius.online", "bigchallenges.ru"
}

BRAND_ROOTS = [
    ("gosuslugi", "gosuslugi.ru"),
    ("sberbank", "sberbank.ru"),
    ("sber", "sber.ru"),
    ("tbank", "tbank.ru"),
    ("tinkoff", "tinkoff.ru"),
    ("vtb", "vtb.ru"),
    ("pochta", "pochta.ru"),
    ("ozon", "ozon.ru"),
    ("wildberries", "wildberries.ru"),
    ("avito", "avito.ru"),
    ("max", "max.ru"),
    ("nalog", "nalog.gov.ru")
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".work", ".buzz", ".monster",
    ".icu", ".vip", ".online", ".site", ".space", ".fun", ".cfd", ".sbs", ".pw"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "clck.ru", "vk.cc", "t.co", "goo.gl",
    "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "u.to"
}

SUSPICIOUS_PATH_KEYWORDS = {
    "login", "verify", "secure", "account", "update", "confirm", "auth",
    "bonus", "prize", "vyplata", "kompensaciya", "vozvrat", "card", "pay",
    "unlock", "security", "recovery", "pasport", "esia"
}


def shannon_entropy(s: str) -> float:
    """Вычисляет информационную энтропию Шеннона H(X) = -sum(p_i * log2(p_i))."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def levenshtein_distance(a: str, b: str) -> int:
    """Вычисляет редакционное расстояние Левенштейна для поиска тайпсквоттинга."""
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = list(range(len(b) + 1))
    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def normalize_homoglyphs(domain: str) -> Tuple[str, bool]:
    """Нормализует подмену латинских букв цифрами и визуально схожими символами."""
    subs = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a'}
    normalized = []
    has_digit_sub = False
    for ch in domain:
        if ch in subs:
            normalized.append(subs[ch])
            has_digit_sub = True
        else:
            normalized.append(ch)
    return "".join(normalized), has_digit_sub


def extract_urls(text: str) -> List[str]:
    """Извлекает все URL-адреса и доменные ссылки из текста сообщения."""
    pattern = r'(https?://[^\s<>"]+|www\.[^\s<>"]+|\b[a-zA-Z0-9.-]+\.(?:ru|com|org|net|online|site|xyz|top|icu|info|io|cc|su|рф|click|space|vip|pw|sbs)(?:/[^\s<>"]*)?)'
    matches = re.findall(pattern, text, flags=re.IGNORECASE)
    cleaned = []
    for m in matches:
        m = m.rstrip(".,!?;:)]}\"'»")
        if not m.startswith(("http://", "https://")):
            m = "http://" + m
        cleaned.append(m)
    return cleaned


def analyze_single_url(url: str) -> Tuple[float, List[str]]:
    """
    Оценивает риск отдельного URL-адреса по 10 структурным и лексическим признакам.
    Возвращает (url_risk in [0, 1], список причин).
    """
    reasons = []
    score = 0.0

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return 0.6, ["Некорректная структура URL-адреса"]

    host = (parsed.netloc or "").lower()
    if ":" in host:
        host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]

    path_query = ((parsed.path or "") + "?" + (parsed.query or "")).lower()

    if host in TRUSTED_DOMAINS or any(host.endswith("." + td) for td in TRUSTED_DOMAINS):
        return 0.02, []

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 0.55
        reasons.append(f"Использование IP-адреса вместо доменного имени ({host})")

    if "xn--" in host:
        score += 0.50
        reasons.append(f"Обнаружена Punycode-кодировка домена ({host}) - возможная подмена символов")

    if host in SHORTENERS:
        score += 0.30
        reasons.append(f"Ссылка скрыта через сервис сокращения URL ({host})")

    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld.lower()):
            score += 0.32
            reasons.append(f"Домен зарегистрирован в зоне повышенного риска ({tld})")
            break

    parts = host.split(".")
    if len(parts) >= 4:
        score += 0.22
        reasons.append(f"Аномальная вложенность поддоменов ({len(parts)} уровней)")
    hyphen_count = host.count("-")
    if hyphen_count >= 2:
        score += 0.25
        reasons.append(f"Множественные дефисы в доменном имени ({host})")
    elif hyphen_count == 1:
        score += 0.12

    domain_body = parts[-2] if len(parts) >= 2 else host
    norm_body, _ = normalize_homoglyphs(domain_body)
    for brand_key, official_dom in BRAND_ROOTS:
        if brand_key in host or brand_key in norm_body:
            score += 0.55
            reasons.append(f"Маскировка под официальный сервис «{official_dom}» (домен {host})")
            break
        dist = levenshtein_distance(norm_body, brand_key)
        if 0 < dist <= 2 and len(brand_key) >= 4:
            score += 0.52
            reasons.append(f"Тайпсквоттинг: домен «{host}» имитирует «{official_dom}» (расстояние Левенштейна d={dist})")
            break

    ent = shannon_entropy(domain_body)
    if ent > 3.70 and len(domain_body) >= 10:
        score += 0.20
        reasons.append(f"Повышенная информационная энтропия домена (H = {ent:.2f} бит/символ)")

    if parsed.scheme == "http":
        score += 0.12

    matched_kw = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path_query]
    if matched_kw:
        score += min(0.30, 0.14 * len(matched_kw))
        reasons.append(f"Фишинговые маркеры в пути ссылки: {', '.join(matched_kw[:3])}")

    if "@" in url or len(url) > 95:
        score += 0.20
        reasons.append("Аномальная длина URL или наличие символа перенаправления '@'")

    return min(1.0, score), reasons


# 3. СЛОВАРЬ ПСИХОЛОГИЧЕСКИХ ТРИГГЕРОВ СОЦИАЛЬНОЙ ИНЖЕНЕРИИ


SOCIAL_ENGINEERING_PATTERNS = {
    "urgency": {
        "weight": 0.24,
        "label": "Искусственное создание дефицита времени и паники",
        "patterns": [
            r"срочно", r"немедленно", r"в течение \d+ минут", r"прямо сейчас",
            r"до конца дня", r"иначе ваш", r"будет заблокирован", r"приостановлен доступ",
            r"незамедлительно", r"осталось \d+ час", r"счет заморожен"
        ]
    },
    "authority_fear": {
        "weight": 0.28,
        "label": "Давление авторитетом или угроза со стороны ведомств/службы безопасности",
        "patterns": [
            r"служб[аы] безопасности", r"следователь", r"центробанк", r"цб рф",
            r"росфинмониторинг", r"фсб", r"мвд", r"прокуратур", r"уголовн\w+ дел",
            r"подозрительн\w+ перевод", r"несанкционированн\w+ вход", r"взлом аккаунта",
            r"оформлен кредит", r"заявк\w+ на кредит", r"безопасн\w+ счет"
        ]
    },
    "credentials_harvesting": {
        "weight": 0.36,
        "label": "Выманивание кодов авторизации, паролей или платежных реквизитов",
        "patterns": [
            r"код из смс", r"смс-код", r"четырехзначный код", r"6-значный код",
            r"назовите код", r"пришлите код", r"cvv", r"cvc", r"пин-код",
            r"три цифры на обороте", r"данные карты", r"пароль от госуслуг",
            r"подтвердите личность", r"введите данные вашей карты", r"продиктуйте код"
        ]
    },
    "financial_lure": {
        "weight": 0.22,
        "label": "Финансовая приманка (обещание выплат, компенсаций, легкого заработка)",
        "patterns": [
            r"положена выплата", r"социальн\w+ компенсаци", r"вы выиграли",
            r"розыгрыш призов", r"гарантированн\w+ доход", r"пассивн\w+ заработок",
            r"получите \d+ ?000 руб", r"возврат ндс", r"начислен бонус",
            r"бесплатн\w+ раздач", r"инвестиц\w+ с доходностью"
        ]
    },
    "impersonation_boss_friend": {
        "weight": 0.24,
        "label": "Ролевая маскировка («сообщение от руководителя» / «помощь знакомому»)",
        "patterns": [
            r"пишу с нового аккаунта", r"одолжи до завтра", r"скинь на карту срочно",
            r"сейчас позвонит куратор", r"проверка сотрудников", r"никому не говорите",
            r"соблюдайте конфиденциальность", r"проголосуй за племянницу", r"проголосуй по ссылке"
        ]
    }
}


def analyze_social_engineering_rules(text: str) -> Tuple[float, List[str]]:
    """Эвристическая оценка текста по категориям приемов социальной инженерии."""
    text_low = text.lower()
    total_score = 0.0
    reasons = []

    for cat_info in SOCIAL_ENGINEERING_PATTERNS.values():
        matched = [pat for pat in cat_info["patterns"] if re.search(pat, text_low)]
        if matched:
            total_score += cat_info["weight"]
            reasons.append(cat_info["label"])

    if len(reasons) >= 2:
        total_score += 0.15

    return min(1.0, total_score), reasons


# 4. СТАТИСТИЧЕСКИЙ ML-КЛАССИФИКАТОР НА БАЗЕ СИМВОЛЬНЫХ N-ГРАММ И НАИВНОГО БАЙЕСА


class CharNgramNaiveBayesClassifier:
    """
    Статистический классификатор текстов на чистом Python + NumPy:
    символьные и словные n-граммы (n=3..5), сублинейный TF-IDF и
    мультиномиальный наивный байесовский классификатор с лапласовским сглаживанием alpha=0.5.
    """

    def __init__(self, n_min: int = 3, n_max: int = 5, max_features: int = 3000, alpha: float = 0.5):
        self.n_min = n_min
        self.n_max = n_max
        self.max_features = max_features
        self.alpha = alpha
        self.vocab: Dict[str, int] = {}
        self.idf: np.ndarray = np.array([])
        self.log_prior: Dict[int, float] = {}
        self.log_likelihood: Dict[int, np.ndarray] = {}

    def _extract_ngrams(self, text: str) -> List[str]:
        clean = re.sub(r"https?://\S+", " URL_TOKEN ", text.lower())
        clean = re.sub(r"[^\w\s]", " ", clean)
        clean = re.sub(r"\s+", " ", clean).strip()
        tokens = []
        words = clean.split()
        tokens.extend(words)
        for i in range(len(words) - 1):
            tokens.append(words[i] + "_" + words[i + 1])
        for w in words:
            padded = f"<{w}>"
            for n in range(self.n_min, self.n_max + 1):
                for i in range(max(0, len(padded) - n + 1)):
                    tokens.append(padded[i:i + n])
        return tokens

    def _vectorize(self, texts: List[str], fit_vocab: bool = False) -> np.ndarray:
        doc_tokens = [self._extract_ngrams(t) for t in texts]
        n_docs = len(texts)

        if fit_vocab:
            df_counts = Counter()
            total_counts = Counter()
            for toks in doc_tokens:
                total_counts.update(toks)
                df_counts.update(set(toks))
            candidates = [tok for tok, cnt in total_counts.most_common() if df_counts[tok] >= 2]
            selected = candidates[:self.max_features]
            self.vocab = {tok: idx for idx, tok in enumerate(selected)}
            self.idf = np.zeros(len(self.vocab), dtype=np.float64)
            for tok, idx in self.vocab.items():
                self.idf[idx] = math.log((1.0 + n_docs) / (1.0 + df_counts[tok])) + 1.0

        X = np.zeros((n_docs, len(self.vocab)), dtype=np.float64)
        for d_idx, toks in enumerate(doc_tokens):
            tf = Counter(toks)
            for tok, cnt in tf.items():
                if tok in self.vocab:
                    f_idx = self.vocab[tok]
                    X[d_idx, f_idx] = (1.0 + math.log(cnt)) * self.idf[f_idx]
            norm = np.linalg.norm(X[d_idx])
            if norm > 0:
                X[d_idx] /= norm
        return X

    def fit(self, texts: List[str], labels: List[int]):
        X = self._vectorize(texts, fit_vocab=True)
        y = np.array(labels)
        for cls in [0, 1]:
            mask = (y == cls)
            self.log_prior[cls] = math.log(np.sum(mask) / len(y))
            feature_sums = np.sum(X[mask], axis=0) + self.alpha
            total_sum = np.sum(feature_sums)
            self.log_likelihood[cls] = np.log(feature_sums / total_sum)

    def predict_proba(self, texts: List[str]) -> np.ndarray:
        X = self._vectorize(texts, fit_vocab=False)
        probs = np.zeros(len(texts), dtype=np.float64)
        for i in range(len(texts)):
            log_p0 = self.log_prior[0] + np.dot(X[i], self.log_likelihood[0]) * 12.0
            log_p1 = self.log_prior[1] + np.dot(X[i], self.log_likelihood[1]) * 12.0
            m = max(log_p0, log_p1)
            p0 = math.exp(log_p0 - m)
            p1 = math.exp(log_p1 - m)
            probs[i] = p1 / (p0 + p1)
        return probs


# 5. ФОРМИРОВАНИЕ РАЗМЕЧЕННОГО ОБУЧАЮЩЕГО И ТЕСТОВӦГО ДАТАСЕТА (N = 200)


def build_benchmark_dataset() -> List[Dict]:
    dataset = []

    cat1_templates = [
        "Уведомление Госуслуги: зафиксирован несанкционированный вход в ваш профиль. Срочно подтвердите личность по ссылке http://gosuslugi-verify-account.xyz/login иначе аккаунт будет заблокирован.",
        "Вам положена социальная компенсация 15 000 руб. Оформите возврат до конца дня в личном кабинете: http://vyplata-gosus1ugi.online/claim",
        "Внимание! В вашем профиле Госуслуг сформирована заявка на кредит. Для отмены немедленно введите СМС-код на портале http://esia-security-gosuslugi.top/cancel",
        "ФНС России: у вас выявлена задолженность. Во избежание блокировки счетов срочно оплатите или сверьте данные: http://nalog-gov-cabinet.icu/pay",
        "Служба поддержки портала Госуслуги: действие вашего полиса ОМС приостановлено. Обновите данные паспорта и карты прямо сейчас: http://gosuslugi-oms-update.site/auth",
    ]
    domains_c1 = [
        "gosuslugi-check.xyz", "gosus1ugi-esia.online", "my-gosuslugi-cabinet.top",
        "gosuslugi-bonus-2026.icu", "esia-recovery-auth.site", "nalog-vyplata.click",
        "gosuslugi-confirm.space", "sfr-kompensaciya.pw", "gosuslugi-security.vip", "esia-pasport-verify.sbs"
    ]
    for i in range(25):
        base = cat1_templates[i % len(cat1_templates)]
        dom = domains_c1[i % len(domains_c1)]
        msg = re.sub(r"http://[^\s]+", f"http://{dom}/session{i+100}/login", base)
        dataset.append({"id": len(dataset) + 1, "text": msg, "label": 1, "category": "phishing_gov"})

    cat2_templates = [
        "Служба безопасности банка: зафиксирован подозрительный перевод на сумму 45 000 руб. Срочно назовите код из СМС или отмените операцию: http://sberbank-secure-cancel.xyz/auth",
        "ЦБ РФ и Росфинмониторинг уведомляют: ваши счета скомпрометированы. Немедленно переведите средства на безопасный счет, иначе ваш счет заморожен: http://cbr-safe-account.top/unlock",
        "Т-Банк: ваша карта временно ограничена. Для разблокировки введите данные вашей карты и три цифры на обороте (CVV) на странице http://tbank-verify-card.online/recovery",
        "ВТБ Онлайн: попытка оформления кредита с вашего устройства! Срочно перейдите в защищенный шлюз http://vtb-security-alert.icu/login и подтвердите отмену.",
        "Предупреждение антифрод-системы: привязка нового номера телефона. Если это не вы, прямо сейчас пройдите верификацию: http://sber-id-protect.site/confirm",
    ]
    domains_c2 = [
        "sberbank-antifraud.xyz", "tbank-security-check.online", "vtb-login-verify.top",
        "cbr-bezopasny-schet.icu", "sber-online-unlock.site", "tinkoff-card-update.click",
        "vtb24-recovery.space", "sberbank-confirm-sms.pw", "alfabank-secure-auth.vip", "mir-pay-verify.sbs"
    ]
    for i in range(25):
        base = cat2_templates[i % len(cat2_templates)]
        dom = domains_c2[i % len(domains_c2)]
        msg = re.sub(r"http://[^\s]+", f"http://{dom}/id{i+200}/verify", base)
        dataset.append({"id": len(dataset) + 1, "text": msg, "label": 1, "category": "phishing_bank"})

    cat3_templates = [
        "Привет! Проголосуй, пожалуйста, за племянницу в конкурсе рисунков, до конца дня не хватает 5 голосов! Авторизация через мессенджер: http://konkurs-deti-vote.xyz/login",
        "Слушай, пишу с нового аккаунта, старый взломали. Одолжи до завтра 6000 руб, скинь на карту срочно, вечером все верну!",
        "Системное уведомление MAX Security: обнаружена подозрительная сессия. Чтобы избежать удаления профиля, пришлите код подтверждения или войдите на http://max-verify-profile.online/auth",
        "Здравствуйте! Это куратор вашей школы. Сейчас вам придет четырехзначный код для электронного дневника, срочно назовите код мне в ответном сообщении.",
        "Экстренная проверка аккаунтов! В течение 15 минут подтвердите номер телефона и введите СМС-код на http://max-account-protection.top/secure иначе доступ будет приостановлен.",
    ]
    domains_c3 = [
        "max-auth-check.xyz", "vote-konkurs-2026.online", "max-messenger-verify.top",
        "golosovanie-deti.icu", "max-security-bot.site", "login-max-profile.click",
        "auth-session-max.space", "konkurs-talant-vote.pw", "max-id-confirm.vip", "verify-account-max.sbs"
    ]
    for i in range(25):
        base = cat3_templates[i % len(cat3_templates)]
        dom = domains_c3[i % len(domains_c3)]
        if "http://" in base:
            msg = re.sub(r"http://[^\s]+", f"http://{dom}/user{i+300}/auth", base)
        else:
            msg = base + f" (код сессии #{i+300})"
        dataset.append({"id": len(dataset) + 1, "text": msg, "label": 1, "category": "social_eng_account"})

    cat4_templates = [
        "Добрый день! Это директор. У нас внеплановая проверка сотрудников со стороны ФСБ и МВД по утечке данных. Сейчас позвонит куратор, соблюдайте конфиденциальность и никому не говорите!",
        "Поздравляем! Вы выиграли в праздничном розыгрыше призов от маркетплейса! Получите 25 000 руб на карту прямо сейчас: http://ozon-prize-bonus.xyz/claim",
        "Следователь главного управления: по вашему счету возбуждено уголовное дело о финансировании. Срочно свяжитесь с дежурным инспектором и назовите реквизиты карты.",
        "Wildberries: возврат средств за отмененный заказ не прошел. Для зачисления денег введите данные вашей карты и CVC-код по ссылке http://wildberries-vozvrat-pay.online/card",
        "Гарантированный доход на инвестициях с доходностью 35% в неделю! Получите выплату уже сегодня после регистрации: http://invest-gazprom-bonus.top/login",
    ]
    domains_c4 = [
        "ozon-bonus-pay.xyz", "wildberries-refund-card.online", "avito-safe-delivery-pay.top",
        "pochta-customs-fee.icu", "gazprom-invest-profit.site", "sber-invest-vyplata.click",
        "wb-prize-winner.space", "ozon-card-verify.pw", "delivery-vozvrat-money.vip", "bonus-payout-2026.sbs"
    ]
    for i in range(25):
        base = cat4_templates[i % len(cat4_templates)]
        dom = domains_c4[i % len(domains_c4)]
        if "http://" in base:
            msg = re.sub(r"http://[^\s]+", f"http://{dom}/order{i+400}/pay", base)
        else:
            msg = base + f" [Уведомление №{i+400}]"
        dataset.append({"id": len(dataset) + 1, "text": msg, "label": 1, "category": "social_eng_lure"})

    cat5_templates = [
        "Ребята, напоминаю, что завтра к третьему уроку нужно сдать лабораторную работу по информатике. Материалы лежат на школьном портале.",
        "Всем привет! Кто участвует в конкурсе «Большие вызовы», проверьте оформление презентации на официальном сайте https://bigchallenges.ru",
        "Расписание консультаций для 10А класса перенесли на четверг в 15:30, кабинет 304. Возьмите с собой тетради по профильной математике.",
        "Регистрация на отборочный этап олимпиады открыта в системе Сириус.Онлайн по адресу https://sirius.online до конца недели.",
        "Маргарита Юрьевна просила передать, что защита учебных проектов состоится в пятницу после уроков в актовом зале.",
    ]
    for i in range(25):
        base = cat5_templates[i % len(cat5_templates)]
        dataset.append({"id": len(dataset) + 1, "text": f"{base} (вариант расписания {i+1})", "label": 0, "category": "legit_school"})

    cat6_templates = [
        "Привет! Ты сегодня пойдешь на тренировку по баскетболу в 18:00 или останешься готовить доклад?",
        "Скинь, пожалуйста, конспект по физике за прошлый урок, я пропустил тему по электродинамике.",
        "Мы договорились встретиться у входа в парк в субботу днем, если погода будет без дождя.",
        "Посмотрел документацию по платформе MAX на https://max.ru - там довольно удобный интерфейс для групповых чатов.",
        "Спасибо за помощь с настройкой Python-окружения, скрипт для построения графиков заработал без ошибок!",
    ]
    for i in range(25):
        base = cat6_templates[i % len(cat6_templates)]
        dataset.append({"id": len(dataset) + 1, "text": f"{base} [{i+1}]", "label": 0, "category": "legit_daily"})

    cat7_templates = [
        "Коллеги, обновил репозиторий проекта. Проверьте, как отрабатывает парсер JSON-ответов при тестировании вебхуков.",
        "Для подключения бота к платформе используйте официальную документацию разработчика https://dev.max.ru и заголовок Authorization.",
        "Сегодня на созвоне в 16:00 обсуждаем архитектуру базы данных и метрики точности классификатора на кросс-валидации.",
        "Настроил логирование времени отклика сервера: средняя задержка при обработке текста составляет около 15 миллисекунд.",
        "Посмотрите аналитический обзор Банка России на официальном сайте https://cbr.ru для раздела со статистикой.",
    ]
    for i in range(25):
        base = cat7_templates[i % len(cat7_templates)]
        dataset.append({"id": len(dataset) + 1, "text": f"{base} (задача #{i+10})", "label": 0, "category": "legit_tech"})

    cat8_templates = [
        "Ваш заказ №4821 доставлен в пункт выдачи. Режим работы пункта и штрихкод доступны в приложении или на сайте https://ozon.ru",
        "Напоминаем о возможности записаться к врачу через официальный портал государственных услуг https://gosuslugi.ru в удобное время.",
        "Информация о тарифах по молодежным дебетовым картам опубликована на официальном сайте банка https://sberbank.ru в разделе частным клиентам.",
        "Посылка прибыла в отделение связи г. Краснознаменск. Отслеживание отправлений доступно на портале https://pochta.ru",
        "Расписание пригородных поездов на выходные дни можно уточнить на официальном ресурсе https://rzd.ru",
    ]
    for i in range(25):
        base = cat8_templates[i % len(cat8_templates)]
        dataset.append({"id": len(dataset) + 1, "text": f"{base} (инфо {i+1})", "label": 0, "category": "legit_service"})

    hard_cases = [
        {"id": 25, "text": "Артем, посмотри документ по нашему проекту, загрузил в облако http://docs-project-share.info/file88", "label": 1, "category": "phishing_gov"},
        {"id": 75, "text": "Подтвердите участие в вебинаре через внешнюю форму http://webinar-school-reg.org/join", "label": 1, "category": "social_eng_account"},
        {"id": 74, "text": "Анна, перекинь, пожалуйста, за обед 450 рублей по номеру, который я пришлю ниже, старую карту закрыл.", "label": 1, "category": "social_eng_account"},
        {"id": 100, "text": "Обновление расписания кружков доступно на внешнем ресурсе http://kruzhok-raspisanie.net/doc", "label": 1, "category": "social_eng_lure"},
        {"id": 125, "text": "На уроке ОБЖ мы разбирали, как мошенники просят назвать код из СМС и пугают службой безопасности банка.", "label": 0, "category": "legit_school"},
        {"id": 175, "text": "В докладе по кибербезопасности нужно описать фишинговые ссылки в зоне .xyz и методы социальной инженерии.", "label": 0, "category": "legit_tech"},
        {"id": 124, "text": "Срочно пришлите до конца дня презентацию проекта в чат, иначе ваш доклад не успеют включить в программу!", "label": 0, "category": "legit_school"},
        {"id": 174, "text": "Тестовый стенд нашей команды развернут на временном домене http://test-stand-school4.site/login для проверки.", "label": 0, "category": "legit_tech"},
    ]
    dataset[24] = hard_cases[0]
    dataset[74] = hard_cases[1]
    dataset[73] = hard_cases[2]
    dataset[99] = hard_cases[3]
    dataset[124] = hard_cases[4]
    dataset[174] = hard_cases[5]
    dataset[123] = hard_cases[6]
    dataset[173] = hard_cases[7]

    return dataset


# 6. ГИБРИДНЫЙ АНАЛИЗАТОР «АНТИФИШИНГ | ЗАЩИТА ЧАТА» И СТЕНД ИСПЫТАНИЙ


class AntiPhishMaxEngine:
    def __init__(self):
        self.classifier = CharNgramNaiveBayesClassifier()
        self.is_trained = False

    def fit(self, texts: List[str], labels: List[int]):
        self.classifier.fit(texts, labels)
        self.is_trained = True

    def analyze_message(self, text: str, ml_prob_override: float = None) -> Dict:
        t0 = time.perf_counter()

        urls = extract_urls(text)
        max_url_score = 0.0
        url_reasons = []
        for u in urls:
            u_score, u_reas = analyze_single_url(u)
            if u_score > max_url_score:
                max_url_score = u_score
            url_reasons.extend(u_reas)

        heur_score, heur_reasons = analyze_social_engineering_rules(text)

        if ml_prob_override is not None:
            ml_score = float(ml_prob_override)
        elif self.is_trained:
            ml_score = float(self.classifier.predict_proba([text])[0])
        else:
            ml_score = 0.0

        if urls:
            combined = 0.42 * max_url_score + 0.33 * heur_score + 0.25 * ml_score
            if max_url_score >= 0.45 and heur_score >= 0.22:
                combined = max(combined, min(1.0, max_url_score + 0.32))
        else:
            combined = 0.55 * heur_score + 0.45 * ml_score
            if heur_score >= 0.48:
                combined = max(combined, 0.78)

        total_risk = float(min(1.0, max(0.0, combined)))

        all_reasons = []
        for r in url_reasons + heur_reasons:
            if r not in all_reasons:
                all_reasons.append(r)
        if ml_score >= 0.65 and not all_reasons:
            all_reasons.append(f"Статистический текстовый анализатор выявил шаблон социальной инженерии (P = {ml_score:.2f})")

        if total_risk >= 0.60:
            verdict = "DANGER"
        elif total_risk >= 0.35:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "url_count": len(urls),
            "url_score": round(max_url_score, 4),
            "heur_score": round(heur_score, 4),
            "ml_score": round(ml_score, 4),
            "total_risk": round(total_risk, 4),
            "verdict": verdict,
            "reasons": all_reasons,
            "latency_ms": round(latency_ms, 3)
        }


def run_experiments_and_generate_charts():
    """Запускает 5-кратную кросс-валидацию на N=200 сообщениях и выводит метрики (флаг --benchmark)."""
    dataset = build_benchmark_dataset()
    texts = [d["text"] for d in dataset]
    y_true = np.array([d["label"] for d in dataset])

    ml_oof_probs = np.zeros(len(dataset), dtype=np.float64)
    pos_idx = np.where(y_true == 1)[0]
    neg_idx = np.where(y_true == 0)[0]
    rng = np.random.default_rng(42)
    rng.shuffle(pos_idx)
    rng.shuffle(neg_idx)

    pos_folds = np.array_split(pos_idx, 5)
    neg_folds = np.array_split(neg_idx, 5)

    for k in range(5):
        val_idx = np.concatenate([pos_folds[k], neg_folds[k]])
        train_idx = np.setdiff1d(np.arange(len(dataset)), val_idx)
        fold_clf = CharNgramNaiveBayesClassifier()
        fold_clf.fit([texts[i] for i in train_idx], [int(y_true[i]) for i in train_idx])
        ml_oof_probs[val_idx] = fold_clf.predict_proba([texts[i] for i in val_idx])

    engine = AntiPhishMaxEngine()
    engine.fit(texts, y_true.tolist())

    url_only_preds, heur_only_preds, ml_only_preds, hybrid_preds, latencies = [], [], [], [], []
    for idx, item in enumerate(dataset):
        res = engine.analyze_message(item["text"], ml_prob_override=ml_oof_probs[idx])
        latencies.append(res["latency_ms"])
        url_only_preds.append(1 if res["url_score"] >= 0.40 else 0)
        heur_only_preds.append(1 if res["heur_score"] >= 0.35 else 0)
        ml_only_preds.append(1 if ml_oof_probs[idx] >= 0.55 else 0)
        hybrid_preds.append(1 if res["total_risk"] >= 0.38 else 0)

    def calc_metrics(preds):
        preds = np.array(preds)
        tp = int(np.sum((y_true == 1) & (preds == 1)))
        tn = int(np.sum((y_true == 0) & (preds == 0)))
        fp = int(np.sum((y_true == 0) & (preds == 1)))
        fn = int(np.sum((y_true == 1) & (preds == 0)))
        acc = (tp + tn) / len(y_true) * 100.0
        prec = tp / max(1, tp + fp) * 100.0
        rec = tp / max(1, tp + fn) * 100.0
        f1 = (2 * prec * rec / max(1e-9, prec + rec))
        fpr = fp / max(1, fp + tn) * 100.0
        return {
            "accuracy": round(acc, 1), "precision": round(prec, 1),
            "recall": round(rec, 1), "f1": round(f1, 1),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn, "fpr": round(fpr, 1)
        }

    metrics_summary = {
        "N_total": len(dataset),
        "url_module": calc_metrics(url_only_preds),
        "heur_module": calc_metrics(heur_only_preds),
        "ml_module": calc_metrics(ml_only_preds),
        "hybrid_complex": calc_metrics(hybrid_preds),
        "avg_latency_ms": round(float(np.mean(latencies)), 2)
    }
    print(json.dumps(metrics_summary, ensure_ascii=False, indent=2))


# 7. ТОЧКА ВХОДА: ОБУЧЕНИЕ МОДЕЛИ И ЗАПУСК БОТА В MAX


if __name__ == "__main__":
    # Если запущен с флагом --benchmark, прогоняем стенд испытаний
    if "--benchmark" in sys.argv:
        run_experiments_and_generate_charts()
        sys.exit(0)

    print("[*] Инициализация комплекса «АнтиФишинг | Защита чата»...")
    dataset = build_benchmark_dataset()
    engine = AntiPhishMaxEngine()
    engine.fit([d["text"] for d in dataset], [d["label"] for d in dataset])
    print(f"[+] ML-модель обучена на выборке N = {len(dataset)} сообщений.")

    bot_client = MaxBotClient(access_token=MAX_BOT_TOKEN)
    bot_client.start_polling(engine)
