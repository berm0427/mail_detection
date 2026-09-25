"""Fetch labeled target/reference URL pairs and save structural ML features."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from email_analyzer.html_pair_features import SCHEMA_VERSION, pair_features
from email_analyzer.page_structure import fetch_page, inspect_structure


def load_side(row, prefix, input_root):
    url = row.get(f'{prefix}_url')
    html_path = row.get(f'{prefix}_html')
    if bool(url) == bool(html_path):
        raise ValueError(f'exactly one of {prefix}_url or {prefix}_html is required')
    if url:
        return fetch_page(url), {'kind': 'url', 'value': url}
    path = Path(html_path)
    if not path.is_absolute():
        path = input_root / path
    content = path.read_bytes()
    if not content.strip():
        return {'status': 'error', 'reason': 'empty_html'}, {'kind': 'html', 'value': str(path)}
    source_url = row.get(f'{prefix}_source_url', '')
    return {'status': 'ok', 'structure': inspect_structure(content, source_url)}, {
        'kind': 'html', 'value': str(path.resolve()), 'source_url': source_url,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path,
                        help='JSONL: target_url or target_html; reference_url or reference_html; label; group_id')
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
            target, target_source = load_side(row, 'target', args.input.parent)
            reference, reference_source = load_side(row, 'reference', args.input.parent)
            if target.get('status') != 'ok' or reference.get('status') != 'ok':
                skipped += 1
                continue
            output = {
                'label': row['label'], 'group_id': str(row['group_id']),
                'target': target_source, 'reference': reference_source,
                'schema_version': SCHEMA_VERSION,
                'features': pair_features(target['structure'], reference['structure']),
            }
            destination.write(json.dumps(output, ensure_ascii=False) + '\n')
            written += 1
    print(json.dumps({'written': written, 'skipped': skipped, 'output': str(args.output)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
