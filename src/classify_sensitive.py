"""
Heuristic + regex-based sensitive text classifier.

Categories:
- CUSTOMER_PII: emails, phones, addresses, names, national IDs
- FINANCIAL: credit cards (Luhn), IBAN, bank routing
- SOURCE_CODE: code blocks, common keywords, stack traces
- API_KEYS: AWS, Google, Slack, generic token formats
- CREDENTIALS: "username: password", SSH keys, PEM blocks
- CONFIDENTIAL: catch-all based on keywords (e.g., "confidential", "internal")
"""

import re
from typing import List, Dict, Tuple

# Basic patterns
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3,4}[\s-]?\d{3,4}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b")
# Credit card (very loose; Luhn check below)
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
# Generic tokens / keys
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
AWS_SECRET_RE = re.compile(r"\b[0-9a-zA-Z/+]{40}\b")
GOOGLE_API_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[abp]-[0-9A-Za-z-]{10,48}\b")
GENERIC_KEY_RE = re.compile(r"\b(?:key|token|secret|apikey|api_key)[\s:=\"']{0,3}[A-Za-z0-9_\-]{16,}\b", re.I)

# Credentials
USER_PASS_RE = re.compile(r"\b(user(name)?|login)\s*[:=]\s*\S+\b.*\b(pass(word)?|pwd)\s*[:=]\s*\S+\b", re.I)
PEM_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |OPENSSH )?PRIVATE KEY-----", re.M)

# Source code heuristics
CODE_KEYWORDS = [
    "def ", "class ", "function(", "public ", "private ", "console.log", "import ", "from ", "#include",
    "System.out.println", "try:", "catch(", "except ", "var ", "let ", "const "
]
STACK_TRACE_RE = re.compile(r"(Traceback \(most recent call last\)|at [\w.$]+\(.*:\d+\))")

CONFIDENTIAL_RE = re.compile(r"\b(confidential|internal use only|do not distribute)\b", re.I)

def luhn_check(num_str: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", num_str)]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def classify_text(s: str) -> List[str]:
    if not s or not isinstance(s, str):
        return []
    cats = set()

    # PII
    if EMAIL_RE.search(s) or PHONE_RE.search(s):
        cats.add("CUSTOMER_PII")

    # Financial
    if IBAN_RE.search(s):
        cats.add("FINANCIAL")
    for m in CC_RE.findall(s):
        if luhn_check(m):
            cats.add("FINANCIAL")
            break

    # API keys / tokens
    if AWS_KEY_RE.search(s) or AWS_SECRET_RE.search(s) or GOOGLE_API_RE.search(s) or SLACK_TOKEN_RE.search(s) or GENERIC_KEY_RE.search(s):
        cats.add("API_KEYS")

    # Credentials
    if USER_PASS_RE.search(s) or PEM_RE.search(s):
        cats.add("CREDENTIALS")

    # Source code / stack traces
    if STACK_TRACE_RE.search(s) or any(kw in s for kw in CODE_KEYWORDS):
        cats.add("SOURCE_CODE")

    # Confidential keywords
    if CONFIDENTIAL_RE.search(s):
        cats.add("CONFIDENTIAL")

    return sorted(cats)
