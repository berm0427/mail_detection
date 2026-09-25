"""Selectively extract phishing HTML from the public Phishpedia remote ZIP."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath

from tools.inspect_remote_zip import RemoteRangeFile


DEFAULT_URL = ('https://drive.usercontent.google.com/download?'
               'id=12ypEMPRQ43zGRqHGut0Esq2z5en0DH4g&export=download&confirm=t')
SOURCE_URL = 'https://github.com/lindsey98/Phishpedia'


def brand_from_folder(folder):
    return re.split(r'\+20\d\d-', folder, maxsplit=1)[0].strip() or 'unknown'


def safe_name(value):
    value = re.sub(r'[^0-9A-Za-z._-]+', '_', value).strip('._')
    return value[:80] or 'unknown'


def parse_info(value):
    """Convert Phishpedia's Python-dict text into JSON-safe metadata."""
    try:
        parsed = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return {'source_info': value} if value else {}
    if not isinstance(parsed, dict):
        return {'source_info': value}
    allowed = ('url', 'host', 'brand', 'sector', 'isotime', 'discover_time',
               'family_id', 'country_code', 'country_name', 'asn', 'asn_name')
    return {key: parsed.get(key) for key in allowed if parsed.get(key) is not None}


def load_manifest(path):
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding='utf-8').splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def normalize_existing_manifest(path):
    rows = load_manifest(path)
    changed = False
    usable = []
    for row in rows:
        if not Path(row.get('html', '')).is_file():
            changed = True
            continue
        raw = row.get('url', '')
        if isinstance(raw, str) and raw.lstrip().startswith('{'):
            metadata = parse_info(raw)
            row.update(metadata)
            changed = True
        usable.append(row)
    rows = usable
    if changed:
        temporary = path.with_suffix('.jsonl.tmp')
        with temporary.open('w', encoding='utf-8', newline='\n') as stream:
            for row in rows:
                stream.write(json.dumps(row, ensure_ascii=False) + '\n')
        temporary.replace(path)
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default=DEFAULT_URL)
    parser.add_argument('--output', type=Path, default=Path('mail_body/training_data/phishpedia_html'))
    parser.add_argument('--max-samples', type=int, default=1000)
    parser.add_argument('--per-brand', type=int, default=20)
    args = parser.parse_args()
    if args.max_samples < 1 or args.per_brand < 1:
        raise ValueError('sample limits must be positive')
    args.output.mkdir(parents=True, exist_ok=True)
    remote = RemoteRangeFile(args.url, chunk_size=512 * 1024, cache_chunks=8)
    with zipfile.ZipFile(remote) as archive:
        html_entries = [entry for entry in archive.infolist()
                        if PurePosixPath(entry.filename).name.casefold() == 'html.txt']
        ranked = sorted(html_entries, key=lambda entry: hashlib.sha256(entry.filename.encode()).digest())
        manifest_path = args.output / 'manifest.jsonl'
        existing = normalize_existing_manifest(manifest_path)
        existing_ids = {row['sample_id'] for row in existing}
        counts = Counter(row.get('brand', 'unknown') for row in existing)
        selected = []
        for entry in ranked:
            if len(existing) + len(selected) >= args.max_samples:
                break
            folder = PurePosixPath(entry.filename).parent.name
            brand = brand_from_folder(folder)
            sample_id = hashlib.sha256(entry.filename.encode()).hexdigest()[:16]
            if sample_id in existing_ids or counts[brand] >= args.per_brand:
                continue
            counts[brand] += 1
            selected.append((entry, brand, folder))
        with manifest_path.open('a', encoding='utf-8', newline='\n') as manifest:
            for index, (entry, brand, folder) in enumerate(selected, len(existing) + 1):
                sample_id = hashlib.sha256(entry.filename.encode()).hexdigest()[:16]
                html_path = args.output / 'html' / safe_name(brand) / f'{sample_id}.html'
                html_path.parent.mkdir(parents=True, exist_ok=True)
                html = archive.read(entry)
                html_path.write_bytes(html)
                info_name = str(PurePosixPath(entry.filename).with_name('info.txt'))
                try:
                    info = archive.read(info_name).decode('utf-8', errors='replace').strip()
                except KeyError:
                    info = ''
                metadata = parse_info(info)
                row = {'sample_id': sample_id, 'label': 1, 'group_id': brand,
                       'brand': brand, 'source_folder': folder, 'source_entry': entry.filename,
                       'html': str(html_path.resolve()),
                       'source': SOURCE_URL, 'license': 'CC0-1.0'}
                row.update(metadata)
                manifest.write(json.dumps(row, ensure_ascii=False) + '\n')
                manifest.flush()
                if index % 25 == 0 or index == args.max_samples:
                    print(f'{index}/{args.max_samples}')
    before_final_check = load_manifest(manifest_path)
    final_rows = normalize_existing_manifest(manifest_path)
    removed_after_write = len(before_final_check) - len(final_rows)
    report = {'samples': len(final_rows),
              'brands': len({row.get('brand', 'unknown') for row in final_rows}),
              'new_samples': len(selected),
              'removed_after_write': removed_after_write,
              'manifest': str(manifest_path),
              'source': SOURCE_URL, 'license': 'CC0-1.0'}
    (args.output / 'SOURCE.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
