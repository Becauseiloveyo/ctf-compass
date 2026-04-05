from __future__ import annotations

import argparse
import json

from ctf_compass.classifier import classify
from ctf_compass.guides import GUIDES


LOCALIZED_NEXT_STEPS = {
    "crypto": {
        "zh-CN": [
            "先判断这是编码、古典密码，还是现代密码误用。",
            "把所有常量、密钥、模数和代数关系完整记下来。",
            "检查重复结构、参数复用和信息泄露点。",
        ],
        "en": [
            "Identify whether this is encoding, classical crypto, or modern crypto misuse.",
            "Write down all provided constants, keys, and algebraic relations.",
            "Look for repetition, structure leaks, and reused parameters.",
        ],
    },
    "web": {
        "zh-CN": [
            "枚举所有路由、参数、会话状态和信任边界。",
            "先锁定最可能的漏洞类别，再进入题目具体测试。",
            "持续记录认证、上传、渲染和服务端请求链路。",
        ],
        "en": [
            "Enumerate endpoints, parameters, sessions, and trust boundaries.",
            "Map the likely vulnerability class before testing challenge-specific inputs.",
            "Keep notes on auth, upload, rendering, and server-side request flows.",
        ],
    },
    "reverse": {
        "zh-CN": [
            "先记录文件类型、架构、字符串、导入表和关键检查点。",
            "先还原验证流程，再考虑 patch 或动态调试。",
            "重点跟踪与 flag 路径相关的常量和变换。",
        ],
        "en": [
            "Record file type, architecture, imports, strings, and obvious guard checks.",
            "Reconstruct the validation flow before patching or dynamic tracing.",
            "Track constants and transformations related to the flag path.",
        ],
    },
    "pwn": {
        "zh-CN": [
            "检查保护项并识别题目预期的内存原语。",
            "记录输入输出行为和崩溃条件。",
            "利用思路只在题目提供的环境中构建。",
        ],
        "en": [
            "Check binary protections and identify the intended memory primitive.",
            "Document input/output behavior and crash conditions.",
            "Build an exploit strategy only for the provided challenge environment.",
        ],
    },
    "forensic": {
        "zh-CN": [
            "列出所有制品类型并保留原始元数据。",
            "从容器、提取文件和网络痕迹中构建时间线。",
            "在深入分析前先检查多层嵌套和隐藏内容。",
        ],
        "en": [
            "List all artifact types and preserve original metadata.",
            "Build a timeline from containers, extracted files, and network traces.",
            "Check for nested content and hidden layers before deeper analysis.",
        ],
    },
    "misc": {
        "zh-CN": [
            "先把问题缩小到更明确的题型。",
            "检查是否能归到编码、隐写、协议或逻辑分析。",
            "在题型未明确前不要先暴力尝试。",
        ],
        "en": [
            "Reduce the problem into a smaller, better-labeled challenge type.",
            "Check for encodings, stego, protocol quirks, or logic constraints.",
            "Avoid brute force before the problem is clearly classified.",
        ],
    },
}


def localize_reason(category: str, matched_count: int, lang: str) -> str:
    if matched_count == 0:
        if lang == "zh-CN":
            return "没有检测到明显的题型关键词，暂时按杂项处理。"
        return "No strong category-specific keywords were detected."
    if lang == "zh-CN":
        return f"检测到 {matched_count} 个与“{category}”相关的关键词。"
    return f"Matched {matched_count} category keyword(s) for '{category}'."


def build_payload(title: str, description: str, tags: list[str], lang: str) -> dict[str, object]:
    result = classify(title, description, tags)
    guide = GUIDES[result.category]
    matched_count = max(0, round((result.confidence - 0.35) / 0.15)) if result.category != "misc" or result.confidence > 0.2 else 0
    return {
        "challenge": {
            "title": title,
            "description": description,
            "tags": tags,
        },
        "classification": {
            "category": result.category,
            "confidence": result.confidence,
            "reason": localize_reason(result.category, matched_count, lang),
            "nextSteps": LOCALIZED_NEXT_STEPS[result.category][lang],
        },
        "guide": {
            "label": guide["label"][lang],
            "summary": guide["summary"][lang],
            "checklist": guide["checklist"][lang],
            "tools": guide["tools"][lang],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ctf-compass-bridge",
        description="Return challenge analysis as JSON for the desktop UI.",
    )
    parser.add_argument("--title", required=True)
    parser.add_argument("--description", default="")
    parser.add_argument("--tags", nargs="*", default=[])
    parser.add_argument("--lang", choices=["zh-CN", "en"], default="zh-CN")
    args = parser.parse_args()

    payload = build_payload(args.title, args.description, args.tags, args.lang)
    print(json.dumps(payload))


if __name__ == "__main__":
    main()
