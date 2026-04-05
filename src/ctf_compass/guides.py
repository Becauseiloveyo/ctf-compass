from __future__ import annotations


GUIDES = {
    "crypto": {
        "label": "Crypto",
        "summary": "Model the math first. Separate encoding from actual cryptanalysis before touching tooling.",
        "checklist": [
            "List every constant, modulus, nonce, ciphertext, and relation.",
            "Decide whether the task is encoding, classical crypto, or modern crypto misuse.",
            "Look for reused parameters, padding clues, or algebraic shortcuts.",
        ],
        "tools": ["CyberChef", "SageMath", "Python notebooks"],
    },
    "web": {
        "label": "Web",
        "summary": "Treat the challenge as an attack surface map. Enumerate routes, state, and trust boundaries before testing payloads.",
        "checklist": [
            "Map endpoints, query/body parameters, cookies, roles, and upload surfaces.",
            "Check auth logic, rendering paths, file handling, and internal fetch behavior inside the challenge boundary.",
            "Confirm the vulnerability class before attempting any challenge-specific exploit chain.",
        ],
        "tools": ["Burp Suite", "Browser DevTools", "ffuf or dirsearch in the CTF target scope"],
    },
    "reverse": {
        "label": "Reverse",
        "summary": "Understand program flow before patching. Constants, checks, and transforms usually reveal the intended path.",
        "checklist": [
            "Record architecture, file type, symbols, strings, and imported APIs.",
            "Trace validation and decoding flows before modifying instructions.",
            "Collect constants and branch conditions related to flag generation.",
        ],
        "tools": ["Ghidra", "IDA Free", "radare2"],
    },
    "pwn": {
        "label": "Pwn",
        "summary": "Start with binary protections and the intended memory primitive. Do not guess the exploit class blindly.",
        "checklist": [
            "Check NX, PIE, RELRO, canaries, and libc assumptions.",
            "Characterize the input model and crash behavior.",
            "Build an exploit strategy only for the provided challenge runtime.",
        ],
        "tools": ["pwndbg", "checksec", "GDB"],
    },
    "forensic": {
        "label": "Forensic",
        "summary": "Preserve evidence and organize artifacts before deeper extraction. Good triage is most of the work.",
        "checklist": [
            "Identify containers, timestamps, and embedded artifact types.",
            "Build a timeline from files, archives, and captures.",
            "Check for nested layers, hidden data, and metadata anomalies.",
        ],
        "tools": ["Autopsy", "Wireshark", "binwalk"],
    },
    "misc": {
        "label": "Misc",
        "summary": "Reduce ambiguity quickly. Many misc problems collapse into encoding, protocol analysis, or stego.",
        "checklist": [
            "Relabel the challenge into a narrower technical type.",
            "Check whether it reduces to encoding, stego, protocol, or logic.",
            "Avoid brute force until the structure is understood.",
        ],
        "tools": ["CyberChef", "Python REPL", "Custom scripts"],
    },
}
