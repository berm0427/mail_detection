"""Sender and link relationship observations without a static registry."""
from email.utils import getaddresses
from html.parser import HTMLParser
from collections import Counter
from .link_evidence import hostname, inspect_html_links, Links

CLICK_LINK = 'click_link'
FORM_ACTION = 'form_action'
PASSIVE_RESOURCE = 'passive_resource'
ACTION_ROLES = frozenset((CLICK_LINK, FORM_ACTION))


def absolute_web_host(value):
    """Resolve only explicit HTTP(S) or protocol-relative HTML targets."""
    raw = str(value or '').strip()
    if not raw.casefold().startswith(('http://', 'https://', '//')):
        return None
    return hostname(raw)

try:
    import tldextract
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except ImportError:
    _TLD_EXTRACT = None

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
        tag = (tag or '').casefold()
        attrs = {str(name).casefold(): value for name, value in attrs}
        self.tags[tag] += 1
        for attr in ('href', 'src', 'action'):
            if attrs.get(attr):
                role = (CLICK_LINK if tag == 'a' and attr == 'href'
                        else FORM_ACTION if tag == 'form' and attr == 'action'
                        else PASSIVE_RESOURCE)
                self.targets.append({
                    'tag': tag,
                    'attribute': attr,
                    'role': role,
                    'host': absolute_web_host(attrs[attr]),
                })
        if tag == 'form':
            action = attrs.get('action', '')
            action_host = absolute_web_host(action)
            self.forms.append({'host': action_host,
                               'status': 'absolute' if action_host else 'relative_or_unspecified'})


def analyze_references(message):
    """Observe sender/link relationships without a local organization registry."""
    sender = sorted({hostname(address.rsplit('@', 1)[1]) for _, address in getaddresses(message.get_all('From', [])) if '@' in address} - {None})
    reply = sorted({hostname(address.rsplit('@', 1)[1]) for _, address in getaddresses(message.get_all('Reply-To', [])) if '@' in address} - {None})
    return_path = sorted({hostname(address.rsplit('@', 1)[1]) for _, address in getaddresses(message.get_all('Return-Path', [])) if '@' in address} - {None})
    htmls = body_html(message); shape = Shape()
    for html in htmls: shape.feed(html)
    relationships_by_host = {}
    for target in shape.targets:
        target_root=registrable_domain(target['host'])
        sender_roots={registrable_domain(h) for h in sender}-{None}
        same_sender_root=bool(target_root and target_root in sender_roots)
        relationship='unresolved' if not target['host'] else 'same_sender_domain' if same_sender_root else 'external_domain'
        key=target['host'] or '(relative_or_missing)'
        current=relationships_by_host.setdefault(key,{'host':target['host'],'tags':set(),
            'relationship':relationship,'registrable_domain':target_root,'roles':set()})
        current['tags'].add(target['tag'])
        current['roles'].add(target['role'])
    relationships=[{**row,'tags':sorted(row['tags']),'roles':sorted(row['roles'])}
                   for row in relationships_by_host.values()]
    return {'status': 'dynamic', 'registered_domains': 0, 'from_hosts': sender, 'reply_to_hosts': reply,
            'from_reply_relation': 'not_observed' if not reply else 'same_hosts' if sender == reply else 'different_hosts',
            'return_path_hosts': return_path,
            'from_return_path_relation': 'not_observed' if not return_path else 'same_hosts' if sender == return_path else 'different_hosts',
            'sender_organizations_observed': [], 'sender_authenticated': False,
            'domain_relationships': relationships, 'forms': shape.forms,
            'claimed_official_links': [], 'official_claim_mismatch_count': 0,
            'template_status': 'retired', 'template_comparisons': [], 'excluded_templates': 0,
            'ml': {'status': 'handled_by_live_discovery'},
            'note': ('발신 주소와 HTML 대상의 동일 기본 도메인 여부를 역할별로 관측합니다. '
                     'ML 외부 행동 특징은 클릭 링크와 폼 제출 대상만 사용하며 정적 리소스와 본문 텍스트 URL은 제외합니다. '
                     '공식 사이트 판단은 실시간 후보 검색과 ML 순위화가 담당합니다.')}
