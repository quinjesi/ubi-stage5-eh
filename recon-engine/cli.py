#!/usr/bin/env python3
#Command-line interface for the recon engine. Parses arguments and hands control over to the core engine.


import argparse
import sys
from pathlib import Path

from engine.core import run


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Recon Engine: Your Discovery Awaits!"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target IP or hostname (e.g., 127.0.0.1)"
    )
    parser.add_argument(
        "--scope",
        required=True,
        help="Path to the scope.csv file"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Directory where all results will be saved"
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=25,
        help="Maximum requests per second (default: 25)"
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    scope_path = Path(args.scope)
    if not scope_path.is_file():
        print(f"ERROR: Scope file not found: {scope_path}", file=sys.stderr)

    if not args.target:
        print("ERROR: --target cannot be empty", file=sys.stderr)
        sys.exit(1)

    run(
        target=args.target,
        scope_path=args.scope,
        output_dir=args.output,
        rate=args.rate
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
