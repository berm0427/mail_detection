"""Website comparison using dynamically discovered official-site candidates."""
from difflib import SequenceMatcher
from email.utils import getaddresses
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit
import tldextract
from .page_structure import analyze_pages
from .html_pair_features import SCHEMA_VERSION, pair_features
from .official_site_discovery import discover_official_sites

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def _site(host):
    part = _EXTRACT(str(host or '').casefold().rstrip('.'))
    return '.'.join(x for x in (part.domain, part.suffix) if x)


def _brand_label(host):
    """Return a comparison-safe domain label, folding common lookalike digits."""
    part = _EXTRACT(str(host or '').casefold().rstrip('.'))
    return part.domain.translate(str.maketrans({'0':'o','1':'i','3':'e','4':'a','5':'s','7':'t'}))


def _observed_hosts(message, pages, links):
    hosts=[]
    for _, address in getaddresses(message.get_all('From', [])):
        if '@' in address:
            hosts.append(('sender', address.rsplit('@', 1)[1].casefold().rstrip('.')))
    for page in pages.get('pages', []):
        if page.get('requested_host'):
            hosts.append(('destination', str(page['requested_host']).casefold().rstrip('.')))
    for item in links.get('links', []):
        if item.get('target_host'):
            hosts.append(('html_link', str(item['target_host']).casefold().rstrip('.')))
    return list(dict.fromkeys(hosts))


def _message_action_links(message):
    """Return clickable HTTP(S) routes embedded in the EML itself.

    Link text is preserved as an observation.  It is not classified with a
    keyword list and page collection is not required.
    """
    rows=[]
    for part in message.walk():
        if part.get_content_disposition() == 'attachment' or part.get_filename():
            continue
        if part.get_content_type() != 'text/html':
            continue
        try:
            soup=BeautifulSoup(part.get_content(), 'html.parser')
        except (LookupError, UnicodeError, ValueError):
            continue
        base_tag=soup.find('base',href=True)
        base=base_tag.get('href') if base_tag else ''
        for anchor in soup.find_all('a',href=True):
            target=urljoin(base,anchor.get('href',''))
            parsed=urlsplit(target)
            if parsed.scheme not in ('http','https') or not parsed.hostname:
                continue
            rows.append({'target_url':target,'target_host':parsed.hostname.casefold().rstrip('.'),
                         'visible_text':' '.join(anchor.stripped_strings)[:240]})
    unique={}
    for row in rows:
        unique.setdefault((row['target_url'],row['visible_text']),row)
    return list(unique.values())


def _official_external_action_routes(message, candidates, pages=None, references=None):
    """Observe official-entity claims routing clicks to unrelated domains.

    This is a compound relationship: a confidently resolved official entity,
    an EML-embedded clickable route, and a destination outside the entity's
    official registrable domain.  It does not depend on the destination page
    remaining online.
    """
    findings=[]
    links=_message_action_links(message)
    collected_by_site={}
    for page in (pages or {}).get('pages', []):
        if page.get('status') != 'ok':
            continue
        site=_site(page.get('requested_host'))
        linked_sites={_site(host) for host in (page.get('structure') or {}).get('link_hosts', [])}
        if site:
            collected_by_site.setdefault(site,set()).update(linked_sites-{''})
    official_links_by_site={}
    for reference in references or []:
        if not reference.get('verified') or (reference.get('fetch') or {}).get('status') != 'ok':
            continue
        official_site=_site(reference.get('host'))
        linked_sites={_site(host) for host in
                      ((reference.get('fetch') or {}).get('structure') or {}).get('link_hosts', [])}
        if official_site:
            official_links_by_site.setdefault(official_site,set()).update(linked_sites-{''})
    for candidate in candidates:
        score=float(candidate.get('ranking_score') or 0)
        official_site=_site(candidate.get('host'))
        if score < .50 or not official_site or float(candidate.get('label_match') or 0) < 1:
            continue
        for link in links:
            target_site=_site(link['target_host'])
            if not target_site or target_site == official_site:
                continue
            # A separately hosted service can still have an observable first-
            # party relationship with the institution.  A link from the
            # collected destination back to the discovered official site is
            # evidence of that relationship, so it is retained as structure
            # but must not be called an unrelated-domain mismatch.
            if (official_site in collected_by_site.get(target_site,set())
                    or target_site in official_links_by_site.get(official_site,set())):
                continue
            findings.append({
                'organization':candidate.get('organization'),
                'entity_id':candidate.get('entity_id'),
                'official_host':candidate.get('host'),
                'official_site':official_site,
                'target_host':link['target_host'],
                'target_site':target_site,
                'target_url':link['target_url'],
                'visible_text':link['visible_text'],
                'discovery_score':score,
                'basis':'explicit_official_claim_external_click_route',
            })
    unique={}
    for row in findings:
        unique.setdefault((row['entity_id'],row['target_site']),row)
    return list(unique.values())


def _official_reference_links_to_target(reference, target_host):
    """Whether collected official HTML directly links the target site."""
    official_links={_site(host) for host in
                    ((reference.get('fetch') or {}).get('structure') or {}).get('link_hosts', [])}
    return bool(_site(target_host) and _site(target_host) in official_links)


def _official_domain_mismatches(message, pages, links, candidates):
    """Find domains that closely imitate a confidently discovered official site.

    A different domain alone is not evidence because legitimate mail commonly
    uses delivery vendors.  We require a high-confidence live candidate and a
    near-identical registrable domain label after common lookalike folding.
    """
    findings=[]
    for candidate in candidates:
        score=float(candidate.get('ranking_score') or 0)
        official_site=_site(candidate.get('host'))
        official_label=_brand_label(candidate.get('host'))
        if score < .50 or len(official_label) < 4:
            continue
        for source, host in _observed_hosts(message, pages, links):
            observed_site=_site(host)
            observed_label=_brand_label(host)
            if not observed_site or observed_site == official_site or len(observed_label) < 4:
                continue
            similarity=SequenceMatcher(None, observed_label, official_label).ratio()
            if similarity < .82:
                continue
            findings.append({'source':source,'observed_host':host,'observed_site':observed_site,
                             'official_host':candidate['host'],'official_site':official_site,
                             'organization':candidate.get('organization'),'entity_id':candidate.get('entity_id'),
                             'discovery_score':score,'brand_similarity':similarity,
                             'basis':'live_entity_official_domain_confusable'})
    unique={}
    for finding in findings:
        key=(finding['observed_site'],finding['official_site'])
        if key not in unique:
            unique[key]={**finding,'sources':[finding['source']]}
        elif finding['source'] not in unique[key]['sources']:
            unique[key]['sources'].append(finding['source'])
    return list(unique.values())


def compare_homepages(message, pages, links, brands=None, disabled=False,
                      semantic_model_path=None):
    if disabled:
        return {'status':'disabled','references':[],'comparisons':[],'reason':'네트워크 비활성화'}
    discovery = discover_official_sites(message, semantic_model_path, disabled=disabled)
    candidates=[{'host':row['host'],'url':row['url'],'verified':True,'source':row['source'],
                 'organization':row['label'],'entity_id':row['entity_id'],'ml_score':row['ml_score'],
                 'ranking_score':row.get('ranking_score'),'label_match':row.get('label_match',0),
                 'basis':'live_entity_search_ml_ranked'} for row in discovery.get('candidates',[])]
    domain_mismatches=_official_domain_mismatches(message,pages,links,candidates)
    refs=[];comparisons=[]
    for candidate in candidates[:2]:
        fetched=analyze_pages([candidate['url']])['pages'][0]
        # A discovered official URL may redirect only inside its registrable site.
        verified=candidate['verified'] and all(_site(hop.get('host')) == _site(candidate['host'])
                                                for hop in fetched.get('hops',[]))
        ref={**candidate,'verified':verified,'fetch':fetched}
        refs.append(ref)
        if not verified or fetched['status']!='ok':continue
        for index,page in enumerate(pages.get('pages',[])):
            if page['status']!='ok':continue
            structure = page.get('structure') or {}
            target_host = page.get('requested_host')
            same_official_site = _site(target_host) == _site(candidate['host'])
            affiliated_service = _official_reference_links_to_target(ref, target_host)
            interactive_target = bool(
                structure.get('password_fields') or structure.get('forms')
                or structure.get('input_count')
            )
            # Comparing every resource or unrelated external link to the sender's
            # homepage creates false positives. Compare registered organization
            # pages, or an unregistered page that actually solicits user input.
            if affiliated_service:
                continue
            if not same_official_site and not interactive_target:
                continue
            features=pair_features(
                page['structure'], fetched['structure'],
                page.get('final_url') or page.get('requested_url') or page.get('url') or '',
            )
            comparisons.append({'page_index':index,'target_host':page.get('requested_host'),'reference_host':candidate['host'],
                'feature_schema_version':SCHEMA_VERSION,'features':features,
                'tag_count_similarity':features['tag_histogram_similarity'],
                'structure_similarity':features['structure_similarity'],
                'password_fields_target':page['structure']['password_fields'],'password_fields_reference':fetched['structure']['password_fields']})
    external_action_routes=_official_external_action_routes(message,candidates,pages,refs)
    return {'status':'compared' if comparisons else 'basic_only','references':refs,'comparisons':comparisons,
            'omitted':max(0,len(candidates)-2),'discovery':discovery,
            'official_domain_mismatches':domain_mismatches,
            'official_domain_mismatch_count':len(domain_mismatches),
            'official_external_action_routes':external_action_routes,
            'official_external_action_route_count':len(external_action_routes),
            'reason':'실시간 공식 사이트 후보를 로컬 문맥 ML로 선택하고 수집 성공 시 비교합니다. 기본 구조 결과는 항상 유지합니다.',
            'note':'두 페이지의 DOM·폼·입력·링크·외부 리소스 구조를 비교한 관측값입니다. 유사도는 화면·동작의 동일성이나 안전 확률이 아닙니다.'}
