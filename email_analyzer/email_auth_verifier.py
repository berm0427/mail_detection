"""Independent email authentication using DNS records and message bytes."""
from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import ipaddress
import re

import dkim
import dns.resolver
import spf
import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def _domain(address: str) -> str:
    value = parseaddr(str(address or ''))[1]
    return value.rsplit('@', 1)[-1].strip().lower().rstrip('.') if '@' in value else ''


def _organizational_domain(domain: str) -> str:
    item = _EXTRACT(domain)
    return '.'.join(part for part in (item.domain, item.suffix) if part)


def _aligned(left: str, right: str, strict: bool) -> bool:
    left, right = left.lower().rstrip('.'), right.lower().rstrip('.')
    return left == right if strict else bool(left and _organizational_domain(left) == _organizational_domain(right))


def _dkim_tags(value: str) -> dict[str, str]:
    return {key.lower(): val.strip() for key, val in re.findall(r'(?:^|;)\s*([a-z]+)\s*=\s*([^;]+)', value, re.I)}


def _public_source_ip(message) -> tuple[str, str]:
    """Best-effort SMTP inputs reconstructed from untrusted stored headers."""
    for received in message.get_all('Received', []):
        text = str(received)
        candidates = re.findall(r'\[([0-9a-f:.]+)\]', text, re.I)
        for candidate in candidates:
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not (address.is_private or address.is_loopback or address.is_reserved):
                helo = (re.search(r'^\s*from\s+([^\s(]+)', text, re.I) or [None, 'unknown.invalid'])[1]
                return str(address), helo.rstrip('.')
    return '', ''


def _dmarc_policy(domain: str) -> dict:
    if not domain:
        return {'status': 'not_found'}
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=5)
    except dns.resolver.NXDOMAIN:
        return {'status': 'not_found'}
    except dns.resolver.NoAnswer:
        return {'status': 'not_found'}
    except dns.exception.Timeout:
        return {'status': 'timeout'}
    except Exception as exc:
        return {'status': 'error', 'error_type': type(exc).__name__}
    for answer in answers:
        record = ''.join(part.decode() if isinstance(part, bytes) else str(part)
                         for part in getattr(answer, 'strings', ())) or answer.to_text().strip('"')
        if record.lower().startswith('v=dmarc1'):
            tags = _dkim_tags(record)
            return {'status': 'found', 'record': record, 'tags': tags}
    return {'status': 'not_found'}


def verify_email_authentication(raw_email: bytes, *, allow_dns: bool = True) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(raw_email)
    from_domain = _domain(message.get('From', ''))
    signatures = message.get_all('DKIM-Signature', [])
    verified_domains, dkim_results = [], []
    verifier = dkim.DKIM(raw_email)
    for index, signature in enumerate(signatures):
        tags = _dkim_tags(str(signature))
        signing_domain = tags.get('d', '').lower().rstrip('.')
        selector = tags.get('s', '')
        try:
            if not allow_dns:
                passed, status = False, 'not_evaluated'
            else:
                passed = bool(verifier.verify(index))
                status = 'pass' if passed else 'fail'
        except Exception as exc:
            passed, status = False, 'temperror' if isinstance(exc, dns.exception.Timeout) else 'error'
        if passed and signing_domain:
            verified_domains.append(signing_domain)
        dkim_results.append({'status': status, 'domain': signing_domain, 'selector': selector})

    dmarc = _dmarc_policy(from_domain) if allow_dns else {'status': 'not_evaluated'}
    dkim_aligned = False
    if dmarc.get('status') == 'found':
        strict = (dmarc.get('tags') or {}).get('adkim', 'r').lower() == 's'
        dkim_aligned = any(_aligned(domain, from_domain, strict) for domain in verified_domains)
    dmarc['dkim_aligned'] = dkim_aligned
    dmarc['status_result'] = 'pass' if dkim_aligned else 'not_evaluated'

    source_ip, helo = _public_source_ip(message)
    envelope_sender = parseaddr(str(message.get('Return-Path', '')))[1]
    spf_result = {'status': 'not_evaluated', 'input_trust': 'untrusted_stored_received_header'}
    if allow_dns and source_ip and envelope_sender:
        try:
            result, explanation = spf.check2(source_ip, envelope_sender, helo or 'unknown.invalid', timeout=10)
            spf_result.update({'status': result, 'explanation': explanation, 'ip': source_ip,
                               'mail_from': envelope_sender, 'helo': helo})
        except Exception as exc:
            spf_result.update({'status': 'error', 'error_type': type(exc).__name__, 'ip': source_ip,
                               'mail_from': envelope_sender, 'helo': helo})
    if verified_domains:
        overall_dkim = 'pass'
    elif any(item['status'] == 'fail' for item in dkim_results):
        overall_dkim = 'fail'
    elif dkim_results and all(item['status'] == 'not_evaluated' for item in dkim_results):
        overall_dkim = 'not_evaluated'
    elif dkim_results:
        overall_dkim = 'error'
    else:
        overall_dkim = 'not_present'
    return {'from_domain': from_domain, 'dkim': {'status': overall_dkim, 'signatures': dkim_results,
            'verified_domains': verified_domains}, 'spf': spf_result, 'dmarc': dmarc}
