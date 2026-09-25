"""Offline observations only: host equality is not proof of ownership or safety."""
from urllib.parse import urlsplit, urljoin
from html.parser import HTMLParser


def hostname(value):
    try:
        value = str(value).strip()
        parsed = urlsplit(value if '://' in value or value.startswith('//') else '//' + value)
        if parsed.scheme and parsed.scheme.lower() not in ('http', 'https'):
            return None
        host = parsed.hostname
        return host.rstrip('.').encode('idna').decode('ascii').lower() if host else None
    except (ValueError, UnicodeError):
        return None


def same_hostname(left, right):
    host = hostname(left)
    return bool(host and host == hostname(right))


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.active, self.base = [], None, None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'base' and self.base is None:
            self.base = attrs.get('href')
        if tag == 'a':
            self.finish()
            self.active = [attrs.get('href', ''), []]

    def handle_data(self, data):
        if self.active is not None:
            self.active[1].append(data)

    def handle_endtag(self, tag):
        if tag == 'a':
            self.finish()

    def finish(self):
        if self.active is not None:
            self.links.append((self.active[0], ''.join(self.active[1]).strip()))
            self.active = None


def inspect_html_links(message):
    findings = []
    html_parts = 0

    def visit(part):
        nonlocal html_parts
        if part.get_content_disposition() == 'attachment' or part.get_filename() or part.get_content_type() == 'message/rfc822':
            return
        if part.is_multipart():
            for child in part.iter_parts():
                visit(child)
            return
        if part.get_content_type() != 'text/html':
            return
        html_parts += 1
        parser = Links()
        parser.feed(part.get_content())
        parser.finish()
        for href, label in parser.links:
            # Only an explicit displayed HTTP(S) address claims a destination.
            if not label.lower().startswith(('http://', 'https://', 'www.')) or any(c.isspace() for c in label):
                continue
            displayed = hostname(label)
            absolute = href.startswith('//') or '://' in href
            resolved = href if absolute else urljoin(parser.base, href) if parser.base else ''
            target = hostname(resolved) if resolved else None
            findings.append({'displayed_host': displayed, 'target_host': target,
                             'status': 'unresolved' if not displayed or not target else 'same_host' if displayed == target else 'different_host',
                             'base_from_message': bool(not absolute and parser.base)})

    visit(message)
    return {'status': 'ok', 'html_parts': html_parts, 'links': findings,
            'different_host_count': sum(x['status'] == 'different_host' for x in findings),
            'note': '문자열 관측입니다. 불일치는 위탁·추적 링크일 수도 있으며, 일치는 안전·기관 소유의 증명이 아닙니다. 네트워크 접속 없음.'}


def collect_href_urls(message):
    """Collect HTTP(S) anchor destinations without fetching; ignore attachments."""
    found = []
    def visit(part):
        if part.get_content_disposition() == 'attachment' or part.get_filename() or part.get_content_type() == 'message/rfc822':
            return
        if part.is_multipart():
            for child in part.iter_parts():
                visit(child)
            return
        if part.get_content_type() != 'text/html':
            return
        parser = Links()
        parser.feed(part.get_content())
        parser.finish()
        for href, _ in parser.links:
            href = (href or '').strip()
            if not href or href.startswith('#'):
                continue
            resolved = 'https:' + href if href.startswith('//') else urljoin(parser.base, href) if parser.base else href
            try:
                scheme = urlsplit(resolved).scheme.lower()
            except ValueError:
                continue
            if scheme in ('http', 'https') and hostname(resolved):
                found.append({'url': resolved, 'source': 'html_href',
                              'base_from_message': bool(parser.base and not urlsplit(href).scheme and not href.startswith('//'))})
    visit(message)
    return found
