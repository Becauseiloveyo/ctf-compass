from __future__ import annotations

import argparse
from textwrap import indent

from ctf_compass.classifier import classify


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-compass",
        description="A safe classifier and methodology assistant for lawful CTF workflows.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Classify a challenge and print next steps.")
    analyze.add_argument("--title", required=True, help="Challenge title.")
    analyze.add_argument("--description", default="", help="Challenge description.")
    analyze.add_argument("--tags", nargs="*", default=[], help="Optional tags.")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        result = classify(args.title, args.description, args.tags)
        steps = "\n".join(f"- {step}" for step in result.next_steps)
        print(f"Category: {result.category}")
        print(f"Confidence: {result.confidence:.2f}")
        print(f"Reason: {result.reason}")
        print("Next steps:")
        print(indent(steps, "  "))


if __name__ == "__main__":
    main()

