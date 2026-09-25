"""Run with: python -m email_analyzer.features path/to/message.eml"""
import argparse
from dataclasses import asdict
from email import policy
from email.parser import BytesParser
import json
from pathlib import Path
import sys

from email_analyzer.engines.feature_engine import FeatureEngine


def main(argv=None):
    parser = argparse.ArgumentParser(description='Extract local numerical email features as JSON.')
    parser.add_argument('email', type=Path, help='Input .eml file')
    args = parser.parse_args(argv)
    try:
        with args.email.open('rb') as stream:
            message = BytesParser(policy=policy.default).parse(stream)
    except OSError as exc:
        print(f'Cannot read input email: {exc}', file=sys.stderr)
        return 2
    result = FeatureEngine().analyze(message)
    print(json.dumps(asdict(result), ensure_ascii=True, allow_nan=False, indent=2))
    return 0 if result.status == 'ok' else 1


if __name__ == '__main__':
    raise SystemExit(main())
