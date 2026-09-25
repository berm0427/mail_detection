"""Versioned, local-only numerical features for parsed MIME emails.

Authentication headers are untrusted observations, not verified results. URLs
are counted as occurrences; no URLs or attachments are opened or executed.
"""
from email.message import Message
from email.utils import getaddresses
from html.parser import HTMLParser
import re
from urllib.parse import urlsplit


class _HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []

    def handle_data(self, data):
        self.text.append(data)

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in ('href', 'src') and value:
                self.links.append(value)


class EmailFeatureExtractor:
    """Stable feature order; all outputs are finite floats, including counts.

    Body length counts decoded plain text and HTML text (including alternative
    representations). Attachment bytes are decoded MIME payload bytes, without
    archive expansion. Multipart attachments are counted as one attachment.
    Domain mismatch compares exact lowercase hostnames, not registrable domains.
    """
    SCHEMA_VERSION = 1
    FEATURE_NAMES = (
        'header_count', 'received_count', 'from_count', 'recipient_count',
        'subject_length', 'reply_to_domain_mismatch', 'authentication_fail_count',
        'plain_part_count', 'html_part_count', 'body_length', 'body_non_ascii_ratio',
        'url_count', 'unique_url_count', 'https_url_ratio', 'ip_url_count',
        'url_userinfo_count', 'max_url_length', 'attachment_count',
        'attachment_bytes', 'executable_attachment_count',
    )
    _URL = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
    _EXECUTABLE = {'.exe', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.scr', '.msi', '.hta'}

    @staticmethod
    def _decode(part):
        payload = part.get_payload(decode=True)
        if payload is None:
            value = part.get_payload()
            return value if isinstance(value, str) else ''
        try:
            return payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
        except (LookupError, UnicodeError):
            return payload.decode('utf-8', errors='replace')

    def extract(self, email: Message) -> dict[str, float]:
        if not isinstance(email, Message):
            raise TypeError('email must be an email.message.Message')
        values = dict.fromkeys(self.FEATURE_NAMES, 0.0)
        def addresses(name):
            return [address for _, address in getaddresses([str(v) for v in email.get_all(name, [])]) if address]
        def domains(name):
            return {a.rsplit('@', 1)[1].lower().rstrip('.') for a in addresses(name) if '@' in a}
        values['header_count'] = len(email.items())
        values['received_count'] = len(email.get_all('Received', []))
        values['from_count'] = len(addresses('From'))
        values['recipient_count'] = sum(len(addresses(k)) for k in ('To', 'Cc', 'Bcc'))
        values['subject_length'] = len(str(email.get('Subject', '')))
        sender, reply = domains('From'), domains('Reply-To')
        values['reply_to_domain_mismatch'] = bool(sender and reply and sender != reply)
        auth = ' '.join(str(v) for v in email.get_all('Authentication-Results', []))
        values['authentication_fail_count'] = len(re.findall(r'\b(?:spf|dkim|dmarc)\s*=\s*fail\b', auth, re.I))
        bodies, urls = [], []

        def visit(part):
            filename = part.get_filename()
            if part.get_content_disposition() == 'attachment' or filename:
                values['attachment_count'] += 1
                if part.is_multipart():
                    size = sum(len(p.get_payload(decode=True) or b'') for p in part.walk() if not p.is_multipart())
                else:
                    size = len(part.get_payload(decode=True) or b'')
                values['attachment_bytes'] += size
                suffix = '.' + str(filename).rsplit('.', 1)[-1].lower() if filename else ''
                values['executable_attachment_count'] += suffix in self._EXECUTABLE
                return
            if part.is_multipart():
                for child in part.get_payload():
                    visit(child)
                return
            kind = part.get_content_type()
            if kind not in ('text/plain', 'text/html'):
                return
            text = self._decode(part)
            if kind == 'text/html':
                values['html_part_count'] += 1
                parser = _HTMLText()
                parser.feed(text)
                text = ' '.join(parser.text)
                urls.extend(u for u in parser.links if u.lower().startswith(('http://', 'https://')))
            else:
                values['plain_part_count'] += 1
            bodies.append(text)
            urls.extend(self._URL.findall(text))

        visit(email)
        body = ''.join(bodies)
        values['body_length'] = len(body)
        values['body_non_ascii_ratio'] = sum(ord(c) > 127 for c in body) / max(len(body), 1)
        values['url_count'] = len(urls)
        values['unique_url_count'] = len(set(urls))
        values['max_url_length'] = max(map(len, urls), default=0)
        https = 0
        import ipaddress
        for url in urls:
            try:
                parsed = urlsplit(url)
                https += parsed.scheme.lower() == 'https'
                values['url_userinfo_count'] += parsed.username is not None
                try:
                    ipaddress.ip_address(parsed.hostname or '')
                    values['ip_url_count'] += 1
                except ValueError:
                    pass
            except ValueError:
                continue
        values['https_url_ratio'] = https / max(len(urls), 1)
        return {name: float(values[name]) for name in self.FEATURE_NAMES}

    def extract_vector(self, email: Message) -> list[float]:
        features = self.extract(email)
        return [features[name] for name in self.FEATURE_NAMES]
