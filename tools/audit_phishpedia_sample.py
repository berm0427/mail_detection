"""Audit the locally sampled Phishpedia HTML corpus."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

from bs4 import BeautifulSoup


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path,
                        default=Path('mail_body/training_data/phishpedia_html/manifest.jsonl'))
    parser.add_argument('--prune-missing', action='store_true')
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.manifest.read_text(encoding='utf-8').splitlines()
            if line.strip()]
    hashes = defaultdict(list)
    missing = []; empty = []; parse_errors = []
    for row in rows:
        path = Path(row['html'])
        if not path.exists():
            missing.append(row['sample_id']); continue
        content = path.read_bytes()
        if not content.strip(): empty.append(row['sample_id'])
        hashes[hashlib.sha256(content).hexdigest()].append(row['sample_id'])
        try: BeautifulSoup(content, 'html.parser')
        except Exception as error: parse_errors.append((row['sample_id'], str(error)))
    report = {
        'rows': len(rows), 'unique_ids': len({row['sample_id'] for row in rows}),
        'brands': len({row.get('brand') for row in rows}),
        'missing_files': len(missing), 'empty_html': len(empty),
        'duplicate_content_groups': sum(len(group) > 1 for group in hashes.values()),
        'duplicate_content_samples': sum(len(group) - 1 for group in hashes.values()),
        'parse_errors': len(parse_errors),
        'real_url_rows': sum(isinstance(row.get('url'), str) and
                             row['url'].startswith(('http://', 'https://')) for row in rows),
        'host_rows': sum(bool(row.get('host')) for row in rows),
        'missing_sample_ids': missing,
        'duplicate_groups': [group for group in hashes.values() if len(group) > 1],
    }
    if args.prune_missing and missing:
        kept = [row for row in rows if row['sample_id'] not in set(missing)]
        temporary = args.manifest.with_suffix('.jsonl.tmp')
        with temporary.open('w', encoding='utf-8', newline='\n') as stream:
            for row in kept:
                stream.write(json.dumps(row, ensure_ascii=False) + '\n')
        temporary.replace(args.manifest)
        report['pruned_missing_rows'] = len(rows) - len(kept)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
