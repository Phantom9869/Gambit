"""Command-line entry point: python -m gambit example.com"""

import argparse
import sys

from gambit.modules import baseline_headers
from gambit.triage import to_json, to_text

# Add new modules here as they are written.
MODULES = [baseline_headers]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="gambit",
        description="Recon-and-triage for the first hour of a web pentest.",
    )
    parser.add_argument("target", help="hostname to check, e.g. example.com")
    parser.add_argument(
        "--json", action="store_true", help="print the report as JSON"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="confirm you own the target or have written permission to test it",
    )
    args = parser.parse_args(argv)

    if not args.yes:
        answer = input(
            f"Do you own {args.target} or have written permission to test it? [y/N] "
        )
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborting: authorization not confirmed.", file=sys.stderr)
            return 1

    findings = []
    for module in MODULES:
        findings.extend(module.run(args.target))

    print(to_json(findings) if args.json else to_text(findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
