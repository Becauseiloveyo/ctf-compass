from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ClassificationResult:
    category: str
    confidence: float
    reason: str
    next_steps: list[str]


KEYWORDS: dict[str, tuple[str, ...]] = {
    "crypto": ("rsa", "aes", "cipher", "nonce", "modulus", "decode", "decrypt"),
    "web": ("http", "cookie", "session", "request", "route", "template", "upload"),
    "reverse": ("binary", "elf", "apk", "ida", "ghidra", "disasm", "symbol"),
    "pwn": ("overflow", "rop", "libc", "heap", "format string", "canary"),
    "forensic": ("pcap", "memory", "disk", "timeline", "metadata", "artifact"),
    "misc": ("stego", "puzzle", "logic", "encoding", "protocol"),
}


DEFAULT_NEXT_STEPS: dict[str, list[str]] = {
    "crypto": [
        "Identify whether this is encoding, classical crypto, or modern crypto misuse.",
        "Write down all provided constants, keys, and algebraic relations.",
        "Look for repetition, structure leaks, and reused parameters.",
    ],
    "web": [
        "Enumerate endpoints, parameters, sessions, and trust boundaries.",
        "Map the likely vulnerability class before testing challenge-specific inputs.",
        "Keep notes on auth, upload, rendering, and server-side request flows.",
    ],
    "reverse": [
        "Record file type, architecture, imports, strings, and obvious guard checks.",
        "Reconstruct the validation flow before patching or dynamic tracing.",
        "Track constants and transformations related to the flag path.",
    ],
    "pwn": [
        "Check binary protections and identify the intended memory primitive.",
        "Document input/output behavior and crash conditions.",
        "Build an exploit strategy only for the provided challenge environment.",
    ],
    "forensic": [
        "List all artifact types and preserve original metadata.",
        "Build a timeline from containers, extracted files, and network traces.",
        "Check for nested content and hidden layers before deeper analysis.",
    ],
    "misc": [
        "Reduce the problem into a smaller, better-labeled challenge type.",
        "Check for encodings, stego, protocol quirks, or logic constraints.",
        "Avoid brute force before the problem is clearly classified.",
    ],
}


def classify(title: str, description: str, tags: list[str]) -> ClassificationResult:
    haystack = " ".join([title, description, *tags]).lower()
    scores: dict[str, int] = {category: 0 for category in KEYWORDS}

    for category, words in KEYWORDS.items():
        for word in words:
            if word in haystack:
                scores[category] += 1

    best_category, best_score = max(scores.items(), key=lambda item: item[1])
    if best_score == 0:
        return ClassificationResult(
            category="misc",
            confidence=0.2,
            reason="No strong category-specific keywords were detected.",
            next_steps=DEFAULT_NEXT_STEPS["misc"],
        )

    confidence = min(0.95, 0.35 + best_score * 0.15)
    return ClassificationResult(
        category=best_category,
        confidence=confidence,
        reason=f"Matched {best_score} category keyword(s) for '{best_category}'.",
        next_steps=DEFAULT_NEXT_STEPS[best_category],
    )
