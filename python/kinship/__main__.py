"""Command line tools: ``python -m kinship keygen``."""

from __future__ import annotations

import argparse

from kinship import _kinship


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kinship", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "keygen",
        help="print a new random 32-byte key as base64; give the same key to every node",
    )
    args = parser.parse_args(argv)
    if args.command == "keygen":
        print(_kinship.generate_key())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
