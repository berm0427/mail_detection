"""Add URL structural features to an existing HTML-pair feature manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from email_analyzer.html_pair_features import FEATURE_NAMES, SCHEMA_VERSION
from email_analyzer.url_features import numeric_url_features


def target_url(row: dict) -> str:
    target = row.get('target') or {}
    return str(target.get('source_url') or target.get('value') or '')


def upgrade(row: dict) -> dict:
    features = dict(row.get('features') or {})
    observed = numeric_url_features(target_url(row))
    features.update({f'target_url_{name}': value for name, value in observed.items()})
    missing = [name for name in FEATURE_NAMES if name not in features]
    if missing:
        raise ValueError(f'missing existing HTML features: {missing}')
    row = dict(row)
    row['schema_version'] = SCHEMA_VERSION
    row['features'] = {name: float(features[name]) for name in FEATURE_NAMES}
    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.source.read_text(encoding='utf-8').splitlines() if line.strip()]
    upgraded = [upgrade(row) for row in rows]
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.destination.write_text(
        ''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in upgraded),
        encoding='utf-8',
    )
    print(json.dumps({'rows': len(upgraded), 'schema_version': SCHEMA_VERSION,
                      'features': len(FEATURE_NAMES), 'output': str(args.destination)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
