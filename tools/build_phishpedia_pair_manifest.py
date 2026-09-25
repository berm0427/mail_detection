"""Build balanced, provenance-preserving HTML pair collection requests."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phish-manifest', type=Path,
                        default=Path('mail_body/training_data/phishpedia_html/manifest.jsonl'))
    parser.add_argument('--brand-pages', type=Path, default=Path('references/html_brand_pages.json'))
    parser.add_argument('--output', type=Path,
                        default=Path('mail_body/training_data/html_pairs/collection_requests.jsonl'))
    args = parser.parse_args()
    config = json.loads(args.brand_pages.read_text(encoding='utf-8'))
    by_alias = {}
    for organization, entry in config['brands'].items():
        for alias in entry['aliases']:
            by_alias[alias.casefold()] = (organization, entry)
    rows = [json.loads(line) for line in args.phish_manifest.read_text(encoding='utf-8').splitlines()
            if line.strip()]
    output = []; seen_html = set(); positive_counts = {}
    for row in rows:
        match = by_alias.get(str(row.get('brand', '')).casefold())
        path = Path(row['html'])
        if not match or not path.is_file(): continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in seen_html: continue
        seen_html.add(digest)
        organization, entry = match
        output.append({'label': 1, 'group_id': organization,
                       'target_html': str(path.resolve()), 'target_source_url': row.get('url', ''),
                       'reference_url': entry['reference_url'], 'source_sample_id': row['sample_id'],
                       'source': row['source'], 'license': row['license']})
        positive_counts[organization] = positive_counts.get(organization, 0) + 1
    for organization, entry in config['brands'].items():
        if not positive_counts.get(organization): continue
        for page in entry['normal_pages']:
            output.append({'label': 0, 'group_id': organization,
                           'target_url': page, 'reference_url': entry['reference_url'],
                           'source': entry['source'], 'reviewed_at': config['reviewed_at']})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('w', encoding='utf-8', newline='\n') as stream:
        for row in output: stream.write(json.dumps(row, ensure_ascii=False) + '\n')
    print(json.dumps({'rows': len(output), 'positive': sum(x['label'] for x in output),
                      'negative': sum(not x['label'] for x in output),
                      'groups': len({x['group_id'] for x in output}), 'output': str(args.output)},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__': main()
