"""Local, provenance-backed observations; no network or automatic safety verdict."""
import hashlib
import json
from datetime import date
from pathlib import Path
from email.utils import getaddresses
from html.parser import HTMLParser
from collections import Counter
from .link_evidence import hostname, inspect_html_links, Links

try:
    import tldextract
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except ImportError:
    _TLD_EXTRACT = None

DEFAULT = Path(__file__).resolve().parents[1] / 'references' / 'registry.json'


def load_registry(path=None):
    path = Path(path or DEFAULT)
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if data.get('schema_version') != 1 or not isinstance(data.get('domains'), list) or not isinstance(data.get('templates'), list):
            raise ValueError('schema')
        domains = []
        for row in data['domains']:
            if row.get('status') != 'verified':
                continue
            if not all(row.get(k) for k in ('organization', 'domain', 'role', 'source', 'verified_at', 'review_due')):
                continue
            verified, due = date.fromisoformat(row['verified_at']), date.fromisoformat(row['review_due'])
            if not verified <= date.today() <= due:
                continue
            domain = hostname(row['domain'])
            if not domain or row['domain'].lower().rstrip('.') != domain:
                continue
            if row['role'] not in ('official', 'delegated_sender', 'delegated_link'):
                continue
            aliases = row.get('aliases', [])
            if not isinstance(aliases, list) or any(not isinstance(x, str) or not x.strip() for x in aliases):
                aliases = []
            domains.append({**row, 'domain': domain, 'aliases': sorted({x.strip() for x in aliases})})
        return {'status': 'ok', 'domains': domains, 'templates': data['templates'], 'root': path.parent}
    except FileNotFoundError:
        return {'status': 'missing', 'domains': [], 'templates': [], 'root': path.parent}
    except (ValueError, TypeError, AttributeError, OSError):
        return {'status': 'invalid', 'domains': [], 'templates': [], 'root': path.parent}


def matches(host, row):
    return bool(host and (host == row['domain'] or row.get('include_subdomains') is True and host.endswith('.' + row['domain'])))


def registrable_domain(host):
    """Return an offline public-suffix-aware organizational domain."""
    host=hostname(host)
    if not host:return None
    if _TLD_EXTRACT is not None:
        parts=_TLD_EXTRACT(host)
        if parts.domain and parts.suffix:return parts.domain+'.'+parts.suffix
    labels=host.split('.')
    return '.'.join(labels[-2:]) if len(labels)>=2 else host


def body_html(message):
    parts = []
    def visit(part):
        if part.get_content_disposition() == 'attachment' or part.get_filename() or part.get_content_type() == 'message/rfc822':
            return
        if part.is_multipart():
            for child in part.iter_parts(): visit(child)
        elif part.get_content_type() == 'text/html': parts.append(part.get_content())
    visit(message)
    return parts


class Shape(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.targets, self.forms = Counter(), [], []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs); self.tags[tag] += 1
        for attr in ('href', 'src', 'action'):
            if attrs.get(attr):
                self.targets.append({'tag': tag, 'host': hostname(attrs[attr]) if attrs[attr].startswith(('http://', 'https://', '//')) else None})
        if tag == 'form':
            action = attrs.get('action', '')
            self.forms.append({'host': hostname(action) if action.startswith(('http://', 'https://', '//')) else None,
                               'status': 'absolute' if action.startswith(('http://', 'https://', '//')) else 'relative_or_unspecified'})


def analyze_references(message, registry_path=None):
    registry = load_registry(registry_path)
    sender = sorted({hostname(address.rsplit('@', 1)[1]) for _, address in getaddresses(message.get_all('From', [])) if '@' in address} - {None})
    reply = sorted({hostname(address.rsplit('@', 1)[1]) for _, address in getaddresses(message.get_all('Reply-To', [])) if '@' in address} - {None})
    linked_rows = [r for r in registry['domains'] if r['role'] in ('official', 'delegated_sender') and any(matches(h, r) for h in sender)] if len(sender) == 1 else []
    organizations = sorted({r['organization'] for r in linked_rows})
    htmls = body_html(message); shape = Shape()
    for html in htmls: shape.feed(html)
    claimed_links = []
    official_rows = [r for r in registry['domains'] if r['role'] == 'official']
    for html in htmls:
        parser = Links(); parser.feed(html); parser.finish()
        for href, label in parser.links:
            label = ' '.join((label or '').split())
            target = hostname(href)
            if not target or not label:
                continue
            for row in official_rows:
                names = {row['organization'], *row.get('aliases', [])}
                claimed = sorted(name for name in names if name.casefold() in label.casefold())
                explicit = bool(claimed and ('공식' in label or 'official' in label.casefold()))
                if not explicit:
                    continue
                allowed = [candidate for candidate in registry['domains']
                           if candidate['organization'] == row['organization']
                           and candidate['role'] in ('official', 'delegated_link')
                           and matches(target, candidate)]
                claimed_links.append({
                    'label': label[:160], 'target_host': target,
                    'organization': row['organization'], 'matched_names': claimed,
                    'relationship': 'registered' if allowed else 'official_claim_mismatch',
                    'allowed_roles': sorted({candidate['role'] for candidate in allowed}),
                })
                break
    relationships_by_host = {}
    for target in shape.targets:
        related = [r for r in registry['domains'] if r['organization'] in organizations and r['role'] in ('official', 'delegated_link') and matches(target['host'], r)]
        target_root=registrable_domain(target['host'])
        sender_roots={registrable_domain(h) for h in sender}-{None}
        same_sender_root=bool(target_root and target_root in sender_roots)
        relationship='registered' if related else 'unresolved' if not target['host'] else 'same_sender_domain' if same_sender_root else 'unregistered'
        key=target['host'] or '(relative_or_missing)'
        current=relationships_by_host.setdefault(key,{'host':target['host'],'tags':set(),
            'relationship':relationship,'registrable_domain':target_root,'roles':set()})
        current['tags'].add(target['tag']);current['roles'].update(r['role'] for r in related)
    relationships=[{**row,'tags':sorted(row['tags']),'roles':sorted(row['roles'])}
                   for row in relationships_by_host.values()]
    comparisons, excluded = [], 0
    for ref in registry['templates']:
        # Only same-medium templates linked to a registered sender organization.
        if ref.get('kind') != 'email_html' or ref.get('status') != 'verified' or ref.get('organization') not in organizations:
            excluded += 1; continue
        try:
            if not ref.get('source') or not ref.get('verified_at') or not date.fromisoformat(ref['verified_at']) <= date.today() <= date.fromisoformat(ref['review_due']):
                raise ValueError('provenance')
            root = registry['root'].resolve(); path = (root / ref['file']).resolve()
            if not path.is_relative_to(root): raise ValueError('path')
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != ref['sha256']: raise ValueError('hash')
            reference = Shape(); reference.feed(raw.decode('utf-8'))
            for index, html in enumerate(htmls):
                current = Shape(); current.feed(html)
                keys = set(current.tags) | set(reference.tags)
                denominator = sum(max(current.tags[k], reference.tags[k]) for k in keys)
                similarity = sum(min(current.tags[k], reference.tags[k]) for k in keys) / denominator if denominator else None
                comparisons.append({'template_id': ref['id'], 'part': index, 'kind': 'email_html', 'tag_count_similarity': similarity, 'exact_bytes': hashlib.sha256(html.encode()).hexdigest() == ref['sha256']})
        except (KeyError, ValueError, TypeError, OSError):
            excluded += 1
    return {'status': registry['status'], 'registered_domains': len(linked_rows), 'from_hosts': sender, 'reply_to_hosts': reply,
            'from_reply_relation': 'not_observed' if not reply else 'same_hosts' if sender == reply else 'different_hosts',
            'sender_organizations_observed': organizations, 'sender_authenticated': False,
            'domain_relationships': relationships, 'forms': shape.forms,
            'claimed_official_links': claimed_links,
            'official_claim_mismatch_count': sum(x['relationship'] == 'official_claim_mismatch' for x in claimed_links),
            'template_status': 'compared' if comparisons else 'no_eligible_reference', 'template_comparisons': comparisons, 'excluded_templates': excluded,
            'ml': {'status': 'not_applied', 'reason': '검증된 HTML 분류 모델과 독립 라벨 평가셋 없음. 본문 ML 점수를 HTML 판정에 재사용하지 않음.'},
            'note': '발신 주소는 주장값입니다. 도메인 등록·HTML 유사도는 인증 성공 또는 안전 판정이 아닙니다. 미등록은 악성의 증거가 아닙니다.'}
