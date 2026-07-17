import argparse
import json
from dataclasses import asdict
from pathlib import Path

from network_arch.validate import validate_architecture


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a network architecture JSON document.")
    parser.add_argument("document", type=Path)
    args = parser.parse_args()

    document = json.loads(args.document.read_text(encoding="utf-8"))
    violations = validate_architecture(document)
    print(json.dumps([asdict(violation) for violation in violations], indent=2))
    raise SystemExit(1 if violations else 0)


if __name__ == "__main__":
    main()
