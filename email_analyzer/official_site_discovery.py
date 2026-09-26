"""Discover official-site candidates online and rank them with local ML.

The runtime does not consult a local organization/domain registry. Wikidata
supplies live P856 candidates and the configured local MiniLM encoder ranks
which entity best matches the mail's sender and subject context.
"""
from __future__ import annotations

import re
import json
import sqlite3
import time
import hashlib
from email.utils import getaddresses
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import requests
import tldextract

from email_analyzer.engines.semantic_ml import preload_semantic_encoder

ENDPOINT = "https://www.wikidata.org/w/api.php"
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
_CACHE = Path(__file__).resolve().parents[1] / 'models' / 'runtime' / 'official_site_discovery.sqlite3'


def _clean(value):
    value = re.sub(r"[<>\[\]{}()\"']", " ", str(value or ""))
    value = re.sub(r"\b(no[ -]?reply|noreply|notification|notify|mail|team)\b", " ", value, flags=re.I)
    return re.sub(r"\s+", " ", value).strip(" .-_@")


def search_terms(message):
    terms = []
    body = message.get_body(preferencelist=("plain", "html")) if hasattr(message, "get_body") else None
    body_text = _clean(body.get_content()) if body is not None else ""
    organization_pattern = re.compile(
        r"[가-힣A-Za-z0-9]{2,24}(?:경찰청|검찰청|시청|구청|공사|은행|대학교|대학|병원|보험|카드|택배|법원|정부|청)"
    )
    # Explicit organization names in the content are stronger discovery
    # queries than a potentially forged sender domain.
    terms.extend(match.group(0) for match in organization_pattern.finditer(body_text))
    for display, address in getaddresses(message.get_all("From", [])):
        if _clean(display):
            terms.append(_clean(display))
        if "@" in address:
            host = address.rsplit("@", 1)[1].casefold().rstrip(".")
            part = _EXTRACT(host)
            if part.domain:
                terms.append(_clean(part.domain.replace("-", " ")))
    subject = _clean(message.get("Subject", ""))
    if subject:
        terms.append(" ".join(subject.split()[:8]))
    return list(dict.fromkeys(term for term in terms if len(term) >= 2))[:6]


def _api(params, timeout):
    full={"format": "json", "origin": "*", **params}
    key=hashlib.sha256(json.dumps(full,sort_keys=True,ensure_ascii=False).encode('utf-8')).hexdigest()
    _CACHE.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(_CACHE) as db:
        db.execute('CREATE TABLE IF NOT EXISTS api_cache (cache_key TEXT PRIMARY KEY, stored_at REAL, payload TEXT)')
        row=db.execute('SELECT stored_at,payload FROM api_cache WHERE cache_key=?',(key,)).fetchone()
        if row and time.time()-row[0] < 30*86400:
            return json.loads(row[1])
    last=None
    for attempt in range(3):
        response = requests.get(
            ENDPOINT, params=full,
            headers={"User-Agent": "DISE-email-analyzer/1.0 (official-site discovery)"},
            timeout=timeout,
        )
        last=response
        if response.status_code != 429:
            response.raise_for_status()
            payload=response.json()
            with sqlite3.connect(_CACHE) as db:
                db.execute('INSERT OR REPLACE INTO api_cache VALUES (?,?,?)',
                           (key,time.time(),json.dumps(payload,ensure_ascii=False)))
            return payload
        if attempt < 2:
            time.sleep(min(2.0, .5 * (2 ** attempt)))
    last.raise_for_status()


def _website_claims(entity):
    values = []
    for claim in (entity.get("claims") or {}).get("P856", []):
        if claim.get("rank") == "deprecated":
            continue
        value = (((claim.get("mainsnak") or {}).get("datavalue") or {}).get("value"))
        parsed = urlsplit(str(value or ""))
        if parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username and not parsed.password:
            values.append(str(value))
    return list(dict.fromkeys(values))


def discover_official_sites(message, semantic_model_path, disabled=False, timeout=5, limit=2):
    if disabled:
        return {"status": "disabled", "queries": [], "candidates": [], "reason": "network_disabled"}
    terms = search_terms(message)
    if not terms:
        return {"status": "no_query", "queries": [], "candidates": []}
    try:
        hits = {}
        for term in terms:
            payload = _api({"action": "wbsearchentities", "search": term, "language": "ko",
                            "uselang": "ko", "type": "item", "limit": 5}, timeout)
            for item in payload.get("search", []):
                hits.setdefault(item["id"], {"id": item["id"], "matched_queries": []})
                hits[item["id"]]["matched_queries"].append(term)
            if len(hits) >= 5:
                break
        if not hits:
            return {"status": "no_candidates", "queries": terms, "candidates": []}
        entities = _api({"action": "wbgetentities", "ids": "|".join(list(hits)[:20]),
                         "props": "labels|descriptions|claims", "languages": "ko|en"}, timeout).get("entities", {})
        raw = []
        for entity_id, entity in entities.items():
            labels = entity.get("labels") or {}
            descriptions = entity.get("descriptions") or {}
            label = (labels.get("ko") or labels.get("en") or {}).get("value", "")
            description = (descriptions.get("ko") or descriptions.get("en") or {}).get("value", "")
            for url in _website_claims(entity):
                raw.append({"entity_id": entity_id, "label": label, "description": description,
                            "url": url, "host": urlsplit(url).hostname.casefold().rstrip("."),
                            "matched_queries": hits.get(entity_id, {}).get("matched_queries", [])})
        if not raw:
            return {"status": "no_official_claims", "queries": terms, "candidates": []}
        encoder = preload_semantic_encoder(Path(semantic_model_path))
        query_text = " | ".join(terms)
        candidate_texts = [f"{row['label']} {row['description']} {row['host']}" for row in raw]
        vectors = encoder.encode([query_text, *candidate_texts], convert_to_numpy=True, normalize_embeddings=True)
        sender_suffixes = set()
        for _, address in getaddresses(message.get_all("From", [])):
            if "@" in address:
                suffix = _EXTRACT(address.rsplit("@", 1)[1]).suffix
                if suffix: sender_suffixes.add(suffix.casefold().split('.')[-1])
        for row, vector in zip(raw, vectors[1:]):
            row["ml_score"] = float(np.dot(vectors[0], vector))
            label_folded = row["label"].casefold()
            row["label_match"] = float(any(q.casefold() in label_folded or label_folded in q.casefold()
                                             for q in row["matched_queries"] if len(q) >= 2))
            row_suffix = _EXTRACT(row["host"]).suffix.casefold().split('.')[-1]
            row["country_tld_match"] = float(bool(row_suffix and row_suffix in sender_suffixes))
            row["ranking_score"] = (0.65 * row["ml_score"] + 0.20 * row["label_match"]
                                    + 0.15 * row["country_tld_match"])
            row["source"] = "wikidata_p856"
        ranked = sorted(raw, key=lambda row: row["ranking_score"], reverse=True)
        accepted = [row for row in ranked if row["ranking_score"] >= 0.45][:limit]
        return {"status": "ranked" if accepted else "low_confidence", "queries": terms,
                "candidates": accepted, "considered": len(ranked),
                "ranking_model": "local_minilm_hybrid_ranker", "top_score": ranked[0]["ranking_score"],
                "top_candidates": ranked[:3]}
    except (requests.RequestException, OSError, ValueError, TypeError, KeyError) as exc:
        return {"status": "error", "queries": terms, "candidates": [],
                "error": f"{type(exc).__name__}: {exc}"}
