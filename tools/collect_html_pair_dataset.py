"""Fetch labeled target/reference URL pairs and save structural ML features."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from email_analyzer.html_pair_features import SCHEMA_VERSION, pair_features
from email_analyzer.page_structure import fetch_page


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path, help='JSONL: target_url, reference_url, label, group_id')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    written = skipped = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.input.open(encoding='utf-8') as source, args.output.open('w', encoding='utf-8') as destination:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get('label') not in (0, 1) or not row.get('group_id'):
                raise ValueError(f'line {line_number}: label 0/1 and group_id are required')
            target = fetch_page(row['target_url'])
            reference = fetch_page(row['reference_url'])
            if target.get('status') != 'ok' or reference.get('status') != 'ok':
                skipped += 1
                continue
            output = {
                'label': row['label'], 'group_id': str(row['group_id']),
                'target_url': row['target_url'], 'reference_url': row['reference_url'],
                'schema_version': SCHEMA_VERSION,
                'features': pair_features(target['structure'], reference['structure']),
            }
            destination.write(json.dumps(output, ensure_ascii=False) + '\n')
            written += 1
    print(json.dumps({'written': written, 'skipped': skipped, 'output': str(args.output)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
