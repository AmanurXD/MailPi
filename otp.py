import re
from html import unescape


POSITIVE_HINTS = {
    "verification code": 10,
    "confirmation code": 10,
    "security code": 9,
    "login code": 9,
    "sign in code": 9,
    "signin code": 9,
    "reset code": 8,
    "access code": 8,
    "one time password": 10,
    "one-time password": 10,
    "passcode": 8,
    "otp": 8,
    "two-factor": 7,
    "2fa": 7,
    "authenticate": 6,
    "authentication": 6,
    "verify": 6,
    "verification": 6,
    "confirm": 6,
    "confirmation": 6,
    "don't share this code": 7,
    "do not share this code": 7,
    "use this code": 7,
    "here is your code": 8,
    "your code is": 8,
}

NEGATIVE_HINTS = {
    "order number": 9,
    "order id": 8,
    "invoice": 7,
    "tracking": 7,
    "phone": 6,
    "fax": 6,
    "zip": 6,
    "postal": 6,
    "amount": 6,
    "total": 6,
    "price": 6,
    "ticket": 5,
    "receipt": 5,
}


def html_to_text(html_body):
    html_body = html_body or ""
    no_script = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html_body)
    no_tags = re.sub(r"(?s)<[^>]+>", " ", no_script)
    return normalize_text(unescape(no_tags))


def normalize_text(text):
    return re.sub(r"\s+", " ", unescape(text or "")).strip()


def get_line(text, start, end):
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()


def numeric_candidates(text):
    pattern = re.compile(r"(?<![A-Za-z0-9])(?:\d[ -]?){3,7}\d(?![A-Za-z0-9])")
    for match in pattern.finditer(text or ""):
        raw = match.group(0)
        normalized = re.sub(r"\D", "", raw)
        if 4 <= len(normalized) <= 8:
            yield {
                "kind": "otp_digit",
                "raw": raw,
                "value": normalized,
                "start": match.start(),
                "end": match.end(),
            }


def alphanumeric_candidates(text):
    pattern = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{5,8}(?![A-Za-z0-9])")
    for match in pattern.finditer(text or ""):
        raw = match.group(0)
        if not re.search(r"[A-Za-z]", raw) or not re.search(r"\d", raw):
            continue
        yield {
            "kind": "otp_mix",
            "raw": raw,
            "value": raw.upper(),
            "start": match.start(),
            "end": match.end(),
        }


def score_occurrence(source_name, source_text, candidate):
    start = candidate["start"]
    end = candidate["end"]
    raw = candidate["raw"]
    value = candidate["value"]
    lower_text = source_text.lower()
    prev_context = lower_text[max(0, start - 120):start]
    next_context = lower_text[end:min(len(source_text), end + 120)]
    context = f"{prev_context} {next_context}"
    line = get_line(source_text, start, end)
    compact_line = re.sub(r"[^A-Za-z0-9]", "", line).upper()

    score = 0
    if source_name == "subject":
        score += 4
    elif source_name == "text":
        score += 2
    else:
        score += 1

    for phrase, weight in POSITIVE_HINTS.items():
        if phrase in context or phrase in line.lower():
            score += weight

    for phrase, weight in NEGATIVE_HINTS.items():
        if phrase in context or phrase in line.lower():
            score -= weight

    if re.search(r"(code|otp|passcode|pin)[^.\n\r]{0,24}$", prev_context):
        score += 8
    if re.search(r"^(?:code|otp|passcode|pin)\s*[:\-]?\s*", line.lower()):
        score += 6
    if compact_line == re.sub(r"[^A-Za-z0-9]", "", raw).upper():
        score += 6
    if candidate["kind"] == "otp_digit" and re.fullmatch(r"\d{4,8}", value):
        score += 4
    if candidate["kind"] == "otp_mix":
        score += 5

    if "http://" in raw.lower() or "https://" in raw.lower():
        score -= 20

    if candidate["kind"] == "otp_digit" and len(value) == 4:
        number = int(value)
        if 1900 <= number <= 2099:
            score -= 8

    return score


def choose_best_candidate(candidates, minimum_score):
    if not candidates:
        return None

    ranked = []
    for item in candidates.values():
        total_score = item["score"] + (len(item["sources"]) - 1) * 4 + (item["hits"] - 1) * 2
        ranked.append((total_score, item))
    ranked.sort(key=lambda pair: pair[0], reverse=True)

    top_score, top_item = ranked[0]
    if top_score < minimum_score:
        return None

    if len(ranked) > 1:
        second_score, second_item = ranked[1]
        if top_item["value"] != second_item["value"] and (top_score - second_score) < 3:
            return None

    return top_item["value"]


def extract_verification_codes(subject="", text_body="", html_body=""):
    sources = [
        ("subject", subject or ""),
        ("text", text_body or ""),
        ("html", html_to_text(html_body)),
    ]
    aggregated = {"otp_digit": {}, "otp_mix": {}}

    for source_name, source_text in sources:
        if not source_text:
            continue
        for candidate in list(numeric_candidates(source_text)) + list(alphanumeric_candidates(source_text)):
            score = score_occurrence(source_name, source_text, candidate)
            bucket = aggregated[candidate["kind"]]
            key = candidate["value"]
            if key not in bucket:
                bucket[key] = {
                    "value": candidate["value"],
                    "score": 0,
                    "hits": 0,
                    "sources": set(),
                }
            bucket[key]["score"] += score
            bucket[key]["hits"] += 1
            bucket[key]["sources"].add(source_name)

    return {
        "otp_digit": choose_best_candidate(aggregated["otp_digit"], minimum_score=13),
        "otp_mix": choose_best_candidate(aggregated["otp_mix"], minimum_score=13),
    }
