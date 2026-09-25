"""Versioned objective evidence and deterministic local text features."""
from __future__ import annotations

import hashlib
import math
import re
from email.message import Message
from html.parser import HTMLParser
from urllib.parse import urlsplit


class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.parts=[]; self.hidden=0
    def handle_starttag(self,tag,attrs):
        if tag in ('script','style','head'): self.hidden += 1
    def handle_endtag(self,tag):
        if tag in ('script','style','head') and self.hidden: self.hidden -= 1
    def handle_data(self,data):
        if not self.hidden: self.parts.append(data)


def message_text(message: Message, limit=100_000):
    parts=[str(message.get('Subject',''))]
    for part in message.walk():
        if part.is_multipart() or part.get_filename() or part.get_content_disposition()=='attachment': continue
        if part.get_content_type() not in ('text/plain','text/html'): continue
        try: value=part.get_content()
        except Exception: continue
        if part.get_content_type()=='text/html':
            parser=_VisibleText();parser.feed(str(value));value=' '.join(parser.parts)
        parts.append(str(value))
    return re.sub(r'\s+',' ',' '.join(parts)).strip().casefold()[:limit]


def hashed_char_ngrams(text, bins=2048):
    """Signed, L2-normalized char 3-5 gram hashing; stable across Python runs."""
    compact=' '+re.sub(r'\s+',' ',text)+' '
    values={}
    for n in (3,4,5):
        for index in range(max(0,len(compact)-n+1)):
            digest=hashlib.blake2b(compact[index:index+n].encode('utf-8'),digest_size=8,person=b'DISEml01').digest()
            number=int.from_bytes(digest,'big');bucket=number % bins
            values[bucket]=values.get(bucket,0.0)+(1.0 if number & (1<<63) else -1.0)
    norm=math.sqrt(sum(value*value for value in values.values())) or 1.0
    return {index:value/norm for index,value in values.items()}


class EvidenceFeatureExtractor:
    SCHEMA_VERSION=1
    FEATURE_NAMES=(
        'url_total','url_risky','url_rule_score','url_http','display_target_mismatch',
        'official_claim_mismatch','from_reply_mismatch','unregistered_link_hosts',
        'page_targets','page_fetch_ok','page_fetch_failed','page_forms','page_password_fields',
        'page_external_forms','page_http_forms','page_iframes','page_scripts',
        'auth_failures','auth_missing','auth_errors','keyword_matches','urgent_action_requests',
        'attachment_count','attachment_megabytes','executable_attachments',
        'attachment_threats','attachment_alerts','attachment_scan_failures',
    )
    CAPS=(20,20,100,20,10,10,1,20,10,10,10,20,20,20,20,50,100,3,3,3,40,10,20,100,20,20,20,20)

    def extract(self,result):
        url=result.get('url_analysis') or {}; analyzed=url.get('analyzed_urls') or []
        links=result.get('link_evidence') or {}; ref=result.get('reference_evidence') or {}
        page=result.get('page_analysis') or {}; pages=page.get('pages') or []
        rules=result.get('rule_result') or {}; auth=rules.get('auth_summary') or {}
        body=result.get('body') or {}; attachments=result.get('attachments') or []
        structures=[item.get('structure') or {} for item in pages if item.get('status')=='ok']
        forms=[form for structure in structures for form in structure.get('forms',[])]
        scans=[item.get('malware_scan') or {} for item in attachments]
        numerical=((result.get('engine_results') or {}).get('numerical_features') or {}).get('details',{}).get('features',{})
        raw={
            'url_total':url.get('total_urls',len(analyzed)),
            'url_risky':sum(bool(item.get('risk_score')) for item in analyzed),
            'url_rule_score':url.get('risk_score',0),
            'url_http':sum(urlsplit(str(item.get('url',''))).scheme.lower()=='http' for item in analyzed),
            'display_target_mismatch':links.get('different_host_count',0),
            'official_claim_mismatch':ref.get('official_claim_mismatch_count',0),
            'from_reply_mismatch':ref.get('from_reply_relation')=='different_hosts',
            'unregistered_link_hosts':sum(item.get('relationship')=='unregistered' for item in ref.get('domain_relationships',[])),
            'page_targets':len(pages)+int(page.get('omitted',0) or 0),'page_fetch_ok':sum(item.get('status')=='ok' for item in pages),
            'page_fetch_failed':sum(item.get('status')!='ok' for item in pages)+int(page.get('omitted',0) or 0),
            'page_forms':len(forms),'page_password_fields':sum(int(s.get('password_fields',0) or 0) for s in structures),
            'page_external_forms':sum(bool(f.get('external_host')) for f in forms),'page_http_forms':sum(bool(f.get('insecure_http')) for f in forms),
            'page_iframes':sum(int(s.get('iframe_count',0) or 0) for s in structures),'page_scripts':sum(int(s.get('script_count',0) or 0) for s in structures),
            'auth_failures':len(auth.get('failures') or []),'auth_missing':len(auth.get('limitations') or []),'auth_errors':len(auth.get('errors') or []),
            'keyword_matches':sum(int(info.get('scoring_count',info.get('count',0)) or 0) for info in (body.get('categories') or {}).values()),
            'urgent_action_requests':sum(x.get('kind')=='urgent_payment_request' for x in body.get('action_signals',[])),
            'attachment_count':len(attachments),'attachment_megabytes':sum(int(x.get('size',0) or 0) for x in attachments)/(1024*1024),
            'executable_attachments':numerical.get('executable_attachment_count',0),
            'attachment_threats':sum(x.get('status')=='threat_detected' for x in scans),'attachment_alerts':sum(x.get('status') in ('alert','suspicious_structure') for x in scans),
            'attachment_scan_failures':sum(x.get('status') in ('error','timeout','unavailable','disabled') for x in scans),
        }
        return {name:float(min(max(float(raw.get(name,0) or 0),0),cap)) for name,cap in zip(self.FEATURE_NAMES,self.CAPS)}

    def vector(self,result):
        values=self.extract(result);return [values[name] for name in self.FEATURE_NAMES]
