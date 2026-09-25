"""Review signals from static native-form evidence, not a phishing probability."""
def html_review(result):
    data=result.get('page_analysis')
    signals=[]
    if data is None:return {'coverage':'not_run','signals':signals}
    pages=data.get('pages',[])
    failures=sum(p.get('status')!='ok' for p in pages)
    coverage='not_run' if data.get('status')=='disabled' else 'partial' if failures or data.get('omitted',0) else 'complete' if pages else 'no_targets'
    for i,page in enumerate(pages):
        if page.get('status')!='ok':continue
        for j,form in enumerate((page.get('structure') or {}).get('forms',[])):
            if 'submittable_password_fields' not in form:
                coverage='partial';continue
            if form['submittable_password_fields']<=0:continue
            for route in form.get('routes',[]):
                if route.get('native_submission_blocked'):continue
                kinds=[]
                if route.get('external_host'):kinds.append('external_password_destination')
                if route.get('insecure_http'):kinds.append('http_password_destination')
                if route.get('method')=='get':kinds.append('password_in_get_request')
                for kind in kinds:
                    signal={'kind':kind,'page_index':i,'form_index':j,'target_host':route.get('target_host')}
                    if signal not in signals:signals.append(signal)
    return {'coverage':coverage,'signals':signals,'failed_pages':failures,'omitted_pages':data.get('omitted',0)}
