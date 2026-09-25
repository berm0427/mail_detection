"""Static native-form observations; does not simulate browser or JavaScript."""
from urllib.parse import urlsplit,urljoin

def disabled(control):
    if control.has_attr('disabled'):return True
    for fieldset in control.find_parents('fieldset',disabled=True):
        legend=fieldset.find('legend',recursive=False)
        if legend is None or not any(p is legend for p in control.parents):return True
    return False

def blocks_forms(policy):
    # Policies are intersected. Only explicit, unambiguous form-action 'none'.
    for value in str(policy or '').split(','):
        seen=set()
        for directive in value.split(';'):
            tokens=directive.split()
            if not tokens:continue
            key=tokens[0].lower()
            if key in seen:continue
            seen.add(key)
            if key=='form-action' and tokens[1:]==["'none'"]:return True
    return False

def form_observations(soup,final_url,csp_header=None):
    base_tag=soup.find('base',href=True)
    base=urljoin(final_url,base_tag['href']) if base_tag else final_url
    nodes=list(soup.find_all(True));order={id(n):i for i,n in enumerate(nodes)}
    metas=[n for n in soup.find_all('meta') if str(n.get('http-equiv','')).lower()=='content-security-policy' and n.find_parent('head') is not None]
    forms=soup.find_all('form');controls=soup.find_all(['input','button','textarea','select'])
    def owner(c):
        if c.has_attr('form'):
            first=soup.find(id=c['form'])
            return first if first is not None and first.name=='form' else None
        return c.find_parent('form')
    output=[]
    for form in forms:
        associated=[c for c in controls if owner(c) is form]
        passwords=[c for c in associated if c.name=='input' and str(c.get('type','')).lower()=='password']
        eligible=[c for c in passwords if not disabled(c) and bool(c.get('name'))]
        blockers=[]
        if blocks_forms(csp_header):blockers.append('response_header')
        if any(order[id(m)]<order[id(form)] and blocks_forms(m.get('content')) for m in metas):blockers.append('preceding_head_meta')
        method=str(form.get('method','get')).lower()
        if method not in ('get','post','dialog'):method='get'
        def route(action,method,source):
            target=urlsplit(urljoin(base,action) if action else final_url)
            return {'source':source,'method':method,'target_host':target.hostname,'external_host':bool(target.hostname and target.hostname!=urlsplit(final_url).hostname),'insecure_http':target.scheme=='http','scheme':target.scheme,'native_submission_blocked':bool(blockers) or method=='dialog'}
        routes=[route(form.get('action'),method,'form')]
        for c in associated:
            typ=str(c.get('type','submit' if c.name=='button' else 'text')).lower()
            if disabled(c) or not (c.name=='button' and typ not in ('button','reset') or c.name=='input' and typ in ('submit','image')):continue
            if c.has_attr('formaction') or c.has_attr('formmethod'):
                meth=str(c.get('formmethod',method)).lower()
                if meth not in ('get','post','dialog'):meth='get'
                routes.append(route(c.get('formaction',form.get('action')),meth,'submit_control'))
        output.append({**routes[0],'password_fields':len(passwords),'disabled_password_fields':sum(disabled(c) for c in passwords),'submittable_password_fields':len(eligible),'unnamed_password_fields':sum(not c.get('name') for c in passwords),'csp_form_action_none_sources':blockers,'routes':routes,'javascript_submission':'not_evaluated'})
    return output
