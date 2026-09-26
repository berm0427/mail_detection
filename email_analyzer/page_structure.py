"""Bounded static HTML inspection. No browser, scripts, forms or cookies."""
import socket
import ipaddress
from urllib.parse import urlsplit, urljoin, urldefrag
from collections import Counter
import urllib3
from bs4 import BeautifulSoup


def _depth(node):
    value = 0
    parent = getattr(node, 'parent', None)
    while parent is not None and getattr(parent, 'name', None) != '[document]':
        value += 1
        parent = getattr(parent, 'parent', None)
    return value


def inspect_structure(html, final_url, csp_header=None):
    soup = BeautifulSoup(html, 'html.parser')
    host = urlsplit(final_url).hostname
    base_tag = soup.find('base', href=True)
    base = urljoin(final_url, base_tag['href']) if base_tag else final_url
    from .form_observations import form_observations
    forms = form_observations(soup, final_url, csp_header)
    tags = soup.find_all(True)
    depths = [_depth(tag) for tag in tags]
    anchors = soup.find_all('a', href=True)
    images = soup.find_all('img', src=True)
    scripts = soup.find_all('script')
    stylesheets = [tag for tag in soup.find_all('link', href=True)
                   if 'stylesheet' in [str(value).casefold() for value in (tag.get('rel') or [])]]
    def external(value):
        target = urlsplit(urljoin(base, str(value))).hostname
        return bool(target and host and target.casefold().rstrip('.') != host.casefold().rstrip('.'))
    resource_hosts = set()
    for tag, attribute in [(x, 'src') for x in images + [x for x in scripts if x.get('src')]] + [(x, 'href') for x in stylesheets]:
        target = urlsplit(urljoin(base, str(tag.get(attribute, '')))).hostname
        if target:
            resource_hosts.add(target.casefold().rstrip('.'))
    visible_text = ' '.join(soup.stripped_strings)
    return {'tag_counts': dict(Counter(t.name for t in tags)),
            'element_count': len(tags),
            'max_depth': max(depths, default=0),
            'mean_depth': (sum(depths) / len(depths)) if depths else 0.0,
            'visible_text_length': len(visible_text),
            'link_count': len(anchors),
            'external_link_count': sum(external(tag['href']) for tag in anchors),
            'image_count': len(images),
            'external_image_count': sum(external(tag['src']) for tag in images),
            'input_count': len(soup.find_all('input')),
            'hidden_input_count': len(soup.select('input[type="hidden" i]')),
            'button_count': len(soup.find_all('button')) + len(soup.select('input[type="submit" i], input[type="button" i]')),
            'stylesheet_count': len(stylesheets),
            'external_stylesheet_count': sum(external(tag['href']) for tag in stylesheets),
            'resource_host_count': len(resource_hosts),
            'forms': forms, 'password_fields': len(soup.select('input[type="password" i]')),
            'iframe_count': len(soup.find_all('iframe')), 'script_count': len(scripts),
            'external_script_count': sum(bool(urlsplit(urljoin(base,t['src'])).hostname != host) for t in soup.find_all('script',src=True)),
            'meta_refresh_count': len(soup.select('meta[http-equiv="refresh" i]'))}


def fetch_page(url, max_bytes=524288, max_redirects=6):
    history=[]
    for hop in range(max_redirects+1):
        url=urldefrag(url)[0]
        p=urlsplit(url)
        if p.scheme not in ('http','https') or not p.hostname or p.username or p.password:
            return {'status':'blocked','reason':'unsupported_url'}
        port=p.port or (443 if p.scheme=='https' else 80)
        if port not in (80,443):return {'status':'blocked','reason':'unsupported_port'}
        addresses=list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(p.hostname,port,type=socket.SOCK_STREAM)))
        if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
            return {'status':'blocked','reason':'non_public_address'}
        # Connect to the checked IP, retaining TLS hostname verification/SNI.
        cls=urllib3.HTTPSConnectionPool if p.scheme=='https' else urllib3.HTTPConnectionPool
        kwargs={'assert_hostname':p.hostname,'server_hostname':p.hostname,'cert_reqs':'CERT_REQUIRED'} if p.scheme=='https' else {}
        pool=cls(addresses[0],port,timeout=urllib3.Timeout(connect=3,read=3),**kwargs)
        response=None
        try:
            path=(p.path or '/')+('?' + p.query if p.query else '')
            response=pool.urlopen('GET',path,headers={'Host':p.netloc,'User-Agent':'EmailStructureInspector/1.0','Accept':'text/html','Accept-Encoding':'identity'},redirect=False,retries=False,preload_content=False)
            history.append({'host':p.hostname,'http_status':response.status})
            if response.status in (301,302,303,307,308):
                if hop==max_redirects:return {'status':'limited','reason':'redirect_limit','hops':history}
                location=response.headers.get('Location')
                if not location:return {'status':'error','reason':'missing_redirect','hops':history}
                url=urljoin(url,location);continue
            if response.status>=400:return {'status':'http_error','reason':f'HTTP {response.status}','hops':history}
            if not any(x in response.headers.get('Content-Type','').lower() for x in ('text/html','application/xhtml+xml')):
                return {'status':'non_html','hops':history}
            data=response.read(max_bytes+1,decode_content=False)
            if len(data)>max_bytes:return {'status':'limited','reason':'size_limit','hops':history}
            if response.headers.get('Content-Encoding','identity').lower() not in ('','identity'):
                return {'status':'limited','reason':'encoded_response','hops':history}
            final_url = str(response.url)
            return {
                'status': 'ok', 'hops': history, 'bytes': len(data),
                'final_url': final_url,
                'structure': inspect_structure(data, final_url, response.headers.get('Content-Security-Policy')),
            }
        finally:
            if response is not None:response.close()
            pool.close()
    return {'status':'limited'}


def analyze_pages(urls, disabled=False, limit=3):
    if disabled:return {'status':'disabled','pages':[]}
    unique=list(dict.fromkeys(urls))
    representatives=[];seen_hosts=set();duplicate_host_urls=0
    for url in unique:
        host=(urlsplit(url).hostname or '').lower().rstrip('.')
        if host and host in seen_hosts:
            duplicate_host_urls+=1
            continue
        if host:seen_hosts.add(host)
        representatives.append(url)
    pages=[]
    for url in representatives[:limit]:
        try:result=fetch_page(url)
        except Exception as exc:result={'status':'error','reason':type(exc).__name__}
        result['requested_url'] = url
        result['requested_host']=urlsplit(url).hostname
        pages.append(result)
    return {'status':'complete','pages':pages,'omitted':max(0,len(representatives)-limit),
            'duplicate_host_urls':duplicate_host_urls,
            'note':'정적 HTML만 분석. 스크립트·폼 제출·하위 리소스 실행 없음. 관측은 악성 확정이나 공식 사이트 비교 결과가 아닙니다.'}
