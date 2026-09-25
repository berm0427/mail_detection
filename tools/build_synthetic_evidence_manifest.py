"""Build inline, label-independent evidence profiles from synthetic metadata."""
from __future__ import annotations
import argparse,json,re
from pathlib import Path
from urllib.parse import urlsplit

EXECUTABLE={'.exe','.com','.scr','.msi','.bat','.cmd','.ps1','.vbs','.js','.jse','.hta','.lnk','.dll'}

def domain(address):
    value=str(address or '').rsplit('@',1)[-1].lower().strip('. ')
    return value[3:] if value.startswith('mx.') else value

def related(left,right):
    left=domain(left);right=domain(right)
    return bool(left and right and (left==right or left.endswith('.'+right) or right.endswith('.'+left)))

def profile(row):
    urls=json.loads(row['urls']) if isinstance(row.get('urls'),str) else list(row.get('urls') or [])
    sender=domain(row.get('from_address'));analyzed=[];relationships=[]
    for url in urls:
        host=(urlsplit(url).hostname or '').lower();mismatch=not related(host,sender)
        analyzed.append({'url':url,'risk_score':20 if mismatch else 0})
        relationships.append({'host':host,'relationship':'unregistered' if mismatch else 'same_sender_domain'})
    failures=[];limitations=[]
    for method,key in (('SPF','spf_result'),('DKIM','dkim_result'),('DMARC','dmarc_result')):
        status=str(row.get(key,'none')).lower()
        (failures if status=='fail' else limitations if status in ('none','neutral','softfail','unknown') else []).append({'method':method,'status':status})
    attachment=[]
    if row.get('has_attachment'):
        name=str(row.get('attachment_name') or 'attachment');suffix=Path(name).suffix.lower()
        attachment=[{'filename':name,'size':0,'malware_scan':{'status':'clean_static'}}]
    official=bool(re.search(r'공식|정부|공공|경찰|세금|민원',str(row.get('subject',''))+' '+str(row.get('body_text',''))))
    mismatch_count=sum(not related(urlsplit(url).hostname or '',sender) for url in urls)
    return {
        'url_analysis':{'total_urls':len(urls),'risk_score':max([x['risk_score'] for x in analyzed] or [0]),'analyzed_urls':analyzed},
        'link_evidence':{'different_host_count':0},
        'reference_evidence':{'official_claim_mismatch_count':mismatch_count if official else 0,
            'from_reply_relation':'same_hosts' if related(sender,row.get('reply_to')) else 'different_hosts',
            'domain_relationships':relationships},
        'page_analysis':{'status':'not_collected','pages':[]},
        'rule_result':{'auth_summary':{'failures':failures,'limitations':limitations,'errors':[]}},
        'body':{'categories':{},'action_signals':[]},'attachments':attachment,
        'engine_results':{'numerical_features':{'details':{'features':{
            'executable_attachment_count':int(bool(attachment and Path(attachment[0]['filename']).suffix.lower() in EXECUTABLE))}}}},
    }

def main():
    parser=argparse.ArgumentParser();parser.add_argument('metadata',type=Path);parser.add_argument('eml_directory',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();rows=[];groups={}
    for line_no,line in enumerate(args.metadata.read_text(encoding='utf-8').splitlines(),1):
        if not line.strip():continue
        row=json.loads(line);split=row.get('split');group=row.get('scenario_id');label=row.get('label_id')
        if split not in ('train','validation','test') or label not in (0,1) or not group:raise ValueError(f'invalid row {line_no}')
        groups.setdefault(group,set()).add(split);eml=(args.eml_directory/f"{row['id']}.eml").resolve()
        if not eml.is_file():raise FileNotFoundError(eml)
        rows.append({'eml':str(eml),'label':label,'split':split,'group_id':group,'analysis':profile(row)})
    if any(len(splits)>1 for splits in groups.values()):raise ValueError('scenario group leakage')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text('\n'.join(json.dumps(row,ensure_ascii=False,separators=(',',':')) for row in rows)+'\n',encoding='utf-8')
    print(json.dumps({'rows':len(rows),'groups':len(groups),'output':str(args.output)},ensure_ascii=False))

if __name__=='__main__':main()
