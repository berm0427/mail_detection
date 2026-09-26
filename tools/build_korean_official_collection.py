"""Discover same-site official pages for normal HTML-pair training rows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

import requests
import tldextract
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
_SKIP_SUFFIXES = ('.pdf', '.hwp', '.hwpx', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.jpg', '.jpeg', '.png', '.gif', '.svg')


def site_key(url: str) -> str:
    item = _EXTRACT(urlsplit(url).hostname or '')
    return '.'.join(part for part in (item.domain, item.suffix) if part)


def normalize(url: str) -> str:
    split = urlsplit(urldefrag(url)[0])
    return urlunsplit((split.scheme.lower(), split.netloc.lower(), split.path or '/', '', ''))


def discover(seed: str, limit: int, timeout: float) -> tuple[list[str], str | None]:
    try:
        response = requests.get(seed, timeout=timeout, allow_redirects=True,
                                headers={'User-Agent': 'DISE research static collector/1.0'})
        response.raise_for_status()
        if 'html' not in response.headers.get('Content-Type', '').lower():
            return [], 'non_html'
        content = response.content[:2_000_000]
        soup = BeautifulSoup(content, 'html.parser')
        root = normalize(response.url)
        key = site_key(root)
        candidates = [root]
        for anchor in soup.find_all('a', href=True):
            candidate = normalize(urljoin(root, anchor['href']))
            parsed = urlsplit(candidate)
            if parsed.scheme not in ('http', 'https') or site_key(candidate) != key:
                continue
            if parsed.path.lower().endswith(_SKIP_SUFFIXES):
                continue
            if candidate not in candidates:
                candidates.append(candidate)
            if len(candidates) >= limit:
                break
        return candidates, None
    except requests.RequestException as exc:
        return [], type(exc).__name__


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('seeds', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--pages-per-site', type=int, default=5)
    parser.add_argument('--timeout', type=float, default=12.0)
    args = parser.parse_args()
    seeds = [json.loads(line) for line in args.seeds.read_text(encoding='utf-8').splitlines() if line.strip()]
    rows, failures = [], []
    for seed in seeds:
        pages, error = discover(seed['reference_url'], args.pages_per_site, args.timeout)
        if error:
            failures.append({'group_id': seed['group_id'], 'url': seed['reference_url'], 'error': error})
            continue
        for page in pages:
            rows.append({'label': 0, 'group_id': seed['group_id'], 'target_url': page,
                         'reference_url': seed['reference_url'], 'source': seed['source'],
                         'reviewed_at': seed['reviewed_at'], 'corpus_role': 'korean_official_normal'})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows), encoding='utf-8')
    report = {'seeds': len(seeds), 'successful_groups': len({row['group_id'] for row in rows}),
              'rows': len(rows), 'failures': failures, 'output': str(args.output)}
    args.output.with_suffix('.report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
