from __future__ import annotations


GUIDES = {
    "crypto": {
        "label": {
            "zh-CN": "密码",
            "en": "Crypto",
        },
        "summary": {
            "zh-CN": "先把数学关系和编码边界理清，再决定是解码、古典密码还是现代密码误用。",
            "en": "Model the math first. Separate encoding from real cryptanalysis before choosing tools.",
        },
        "checklist": {
            "zh-CN": [
                "列出所有常量、模数、随机数、密文和已知关系。",
                "先判断这是编码问题、古典密码，还是现代密码实现误用。",
                "检查参数复用、填充痕迹、结构泄露和可利用的数学捷径。",
            ],
            "en": [
                "List every constant, modulus, nonce, ciphertext, and known relation.",
                "Decide whether the task is encoding, classical crypto, or modern crypto misuse.",
                "Look for reused parameters, padding clues, structural leaks, and algebraic shortcuts.",
            ],
        },
        "tools": {
            "zh-CN": ["CyberChef", "SageMath", "Python 笔记本"],
            "en": ["CyberChef", "SageMath", "Python notebooks"],
        },
    },
    "web": {
        "label": {
            "zh-CN": "Web",
            "en": "Web",
        },
        "summary": {
            "zh-CN": "把题目当成攻击面梳理任务，先枚举路由、状态和信任边界，再判断漏洞类别。",
            "en": "Treat the challenge as an attack-surface map. Enumerate routes, state, and trust boundaries before testing payloads.",
        },
        "checklist": {
            "zh-CN": [
                "梳理所有路由、参数、Cookie、角色和上传入口。",
                "检查认证逻辑、模板渲染、文件处理和服务端内部请求行为，但仅限题目环境。",
                "先确认漏洞类别，再进入题目特定利用链。",
            ],
            "en": [
                "Map endpoints, query/body parameters, cookies, roles, and upload surfaces.",
                "Check auth logic, rendering paths, file handling, and internal fetch behavior inside the challenge boundary.",
                "Confirm the vulnerability class before attempting any challenge-specific exploit chain.",
            ],
        },
        "tools": {
            "zh-CN": ["Burp Suite", "浏览器开发者工具", "ffuf 或 dirsearch"],
            "en": ["Burp Suite", "Browser DevTools", "ffuf or dirsearch"],
        },
    },
    "reverse": {
        "label": {
            "zh-CN": "逆向",
            "en": "Reverse",
        },
        "summary": {
            "zh-CN": "先理解程序流程，再考虑 patch 或动态调试。常量、比较和变换路径通常就是突破口。",
            "en": "Understand program flow before patching. Constants, checks, and transforms usually reveal the intended path.",
        },
        "checklist": {
            "zh-CN": [
                "记录架构、文件类型、符号、字符串和导入函数。",
                "先还原校验和解码流程，再考虑 patch 或跟踪。",
                "重点收集与 flag 生成相关的常量和分支条件。",
            ],
            "en": [
                "Record architecture, file type, symbols, strings, and imported APIs.",
                "Trace validation and decoding flows before modifying instructions.",
                "Collect constants and branch conditions related to flag generation.",
            ],
        },
        "tools": {
            "zh-CN": ["Ghidra", "IDA Free", "radare2"],
            "en": ["Ghidra", "IDA Free", "radare2"],
        },
    },
    "pwn": {
        "label": {
            "zh-CN": "Pwn",
            "en": "Pwn",
        },
        "summary": {
            "zh-CN": "从二进制保护和预期内存原语入手，不要在没定性前盲猜利用类型。",
            "en": "Start with binary protections and the intended memory primitive. Do not guess the exploit class blindly.",
        },
        "checklist": {
            "zh-CN": [
                "检查 NX、PIE、RELRO、Canary 和 libc 假设。",
                "确认输入输出模型以及崩溃触发条件。",
                "利用思路只针对题目给定运行环境构建。",
            ],
            "en": [
                "Check NX, PIE, RELRO, canaries, and libc assumptions.",
                "Characterize the input model and crash behavior.",
                "Build an exploit strategy only for the provided challenge runtime.",
            ],
        },
        "tools": {
            "zh-CN": ["pwndbg", "checksec", "GDB"],
            "en": ["pwndbg", "checksec", "GDB"],
        },
    },
    "forensic": {
        "label": {
            "zh-CN": "取证",
            "en": "Forensic",
        },
        "summary": {
            "zh-CN": "先保全证据和整理制品，再做深入提取。很多题其实赢在前期整理。",
            "en": "Preserve evidence and organize artifacts before deeper extraction. Good triage is most of the work.",
        },
        "checklist": {
            "zh-CN": [
                "识别容器类型、时间戳和嵌入制品。",
                "从文件、压缩包和抓包中构建时间线。",
                "检查多层嵌套、隐藏数据和异常元数据。",
            ],
            "en": [
                "Identify containers, timestamps, and embedded artifact types.",
                "Build a timeline from files, archives, and captures.",
                "Check for nested layers, hidden data, and metadata anomalies.",
            ],
        },
        "tools": {
            "zh-CN": ["Autopsy", "Wireshark", "binwalk"],
            "en": ["Autopsy", "Wireshark", "binwalk"],
        },
    },
    "misc": {
        "label": {
            "zh-CN": "杂项",
            "en": "Misc",
        },
        "summary": {
            "zh-CN": "尽快把题目缩小到更明确的技术类别。很多 misc 最终都会归到编码、协议或隐写。",
            "en": "Reduce ambiguity quickly. Many misc problems collapse into encoding, protocol analysis, or stego.",
        },
        "checklist": {
            "zh-CN": [
                "先把题目重新归到更窄的技术类型。",
                "检查是否本质上是编码、隐写、协议或逻辑题。",
                "在结构没看明白前不要先暴力枚举。",
            ],
            "en": [
                "Relabel the challenge into a narrower technical type.",
                "Check whether it reduces to encoding, stego, protocol, or logic.",
                "Avoid brute force until the structure is understood.",
            ],
        },
        "tools": {
            "zh-CN": ["CyberChef", "Python REPL", "自定义脚本"],
            "en": ["CyberChef", "Python REPL", "Custom scripts"],
        },
    },
}
