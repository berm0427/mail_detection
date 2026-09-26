"""Versioned objective evidence and deterministic local text features."""
from __future__ import annotations

import re
from email.message import Message
from html.parser import HTMLParser


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
