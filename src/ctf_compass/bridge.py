from __future__ import annotations

import argparse
import json

from ctf_compass.classifier import classify
from ctf_compass.guides import GUIDES


def build_payload(title: str, description: str, tags: list[str]) -> dict[str, object]:
    result = classify(title, description, tags)
    guide = GUIDES[result.category]
    return {
        "challenge": {
            "title": title,
            "description": description,
            "tags": tags,
        },
        "classification": {
            "category": result.category,
            "confidence": result.confidence,
            "reason": result.reason,
            "nextSteps": result.next_steps,
        },
        "guide": guide,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ctf-compass-bridge",
        description="Return challenge analysis as JSON for the desktop UI.",
    )
    parser.add_argument("--title", required=True)
    parser.add_argument("--description", default="")
    parser.add_argument("--tags", nargs="*", default=[])
    args = parser.parse_args()

    payload = build_payload(args.title, args.description, args.tags)
    print(json.dumps(payload))


if __name__ == "__main__":
    main()

