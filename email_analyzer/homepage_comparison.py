"""Website-to-website comparison with explicitly separated candidate provenance."""
from email.utils import getaddresses
from .link_evidence import hostname
from .reference_evidence import load_registry, matches
from .page_structure import analyze_pages


def compare_homepages(message, pages, links, brands=None, registry_path=None, disabled=False):
    if disabled:
        return {'status':'disabled','references':[],'comparisons':[],'reason':'네트워크 비활성화'}
    registry=load_registry(registry_path)
    senders={hostname(a.rsplit('@',1)[1]) for _,a in getaddresses(message.get_all('From',[])) if '@' in a} - {None}
    display={x.get('displayed_host') for x in links.get('links',[])} - {None}
    names={str(x).casefold() for x in (brands or {}).get('extracted_brands',[])}
    orgs={r['organization'] for r in registry['domains'] if r['organization'].casefold() in names or any(matches(h,r) for h in senders|display)}
    candidates=[]
    for r in registry['domains']:
        if r['role']=='official' and r['organization'] in orgs:
            candidates.append({'host':r['domain'],'verified':True,'source':r['source'],'organization':r['organization'],'basis':'reviewed_registry'})
    known={x['host'] for x in candidates}
    for h in sorted(display|senders):
        if h not in known:
            candidates.append({'host':h,'verified':False,'basis':'displayed_address' if h in display else 'claimed_sender'})
    refs=[];comparisons=[]
    for candidate in candidates[:2]:
        fetched=analyze_pages(['https://'+candidate['host']+'/'])['pages'][0]
        # A redirect cannot silently promote a different host to official status.
        verified=candidate['verified'] and all(any(r['role']=='official' and r['organization']==candidate.get('organization') and matches(hop['host'],r) for r in registry['domains']) for hop in fetched.get('hops',[]))
        ref={**candidate,'verified':verified,'fetch':fetched}
        refs.append(ref)
        if not verified or fetched['status']!='ok':continue
        for index,page in enumerate(pages.get('pages',[])):
            if page['status']!='ok':continue
            a=page['structure']['tag_counts'];b=fetched['structure']['tag_counts'];keys=set(a)|set(b)
            denom=sum(max(a.get(k,0),b.get(k,0)) for k in keys)
            comparisons.append({'page_index':index,'target_host':page.get('requested_host'),'reference_host':candidate['host'],
                'tag_count_similarity':sum(min(a.get(k,0),b.get(k,0)) for k in keys)/denom if denom else None,
                'password_fields_target':page['structure']['password_fields'],'password_fields_reference':fetched['structure']['password_fields']})
    return {'status':'compared' if comparisons else 'basic_only','references':refs,'comparisons':comparisons,
            'omitted':max(0,len(candidates)-2),'registry_status':registry['status'],
            'reason':'공식 근거와 수집 성공이 모두 있는 경우에만 비교합니다. 후보 접속 성공은 공식성 증명이 아닙니다. 기본 구조 결과는 유지합니다.',
            'note':'웹페이지끼리 태그 개수 구성을 비교한 참고 수치입니다. 화면·동작의 동일성 또는 안전성 점수가 아니며 홈페이지와 하위 페이지의 차이도 반영됩니다.'}
