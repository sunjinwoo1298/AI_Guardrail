import re

INJECTION_PATTERNS = [
    r"ignore (?:all|previous|any) instructions",
    r"reveal (?:the )?(?:system|developer) prompt",
    r"show (?:me )?(?:the )?(?:system|developer) prompt",
    r"you are now (?:in )?admin(?:istrator)?",
    r"system override",
    r"bypass safety",
    r"act as administrator",
    r"disregard (?:the )?(?:rules|instructions)",
    r"prompt injection",
]

INJECTION_WEIGHTS = {
    "ignore": 0.35,
    "reveal": 0.45,
    "admin": 0.35,
    "override": 0.45,
    "bypass": 0.45,
}


def detect_prompt_injection(text: str):
    matches = []
    lowered_text = text.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lowered_text, flags=re.IGNORECASE):
            matches.append(pattern)

    return matches