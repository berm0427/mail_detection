"""Presentation of independent evidence; never turns missing results into safety."""
import math


STATUS_LABELS = {'ok': '정상', 'error': '오류', 'skipped': '구성 안 됨', 'missing': '결과 없음'}


def engine_rows(result):
    """Return (engine, status, observation, evidence) rows without interpreting HTML."""
    engines = result.get('engine_results') or {}
    rules = result.get('rule_result') or result
    failed = rules.get('verdict') == 'error' or 'risk_score' not in rules
    rule_evidence = '\n'.join(rules.get('reasons') or []) or '추가 근거 없음'
    auth = rules.get('auth_summary') or {}
    auth_lines = []
    for item in auth.get('failures') or []:
        status = item.get('status')
        label = '원문 관측 실패' if status == 'unverified_fail' else '명시적 실패'
        auth_lines.append(f"{item.get('method')} {label}: {status}")
    for item in auth.get('limitations') or []:
        auth_lines.append(f"{item.get('method')} 판정 제외 · 검증 자료 없음: {item.get('status')}")
    for item in auth.get('errors') or []:
        auth_lines.append(f"{item.get('method')} 조회 오류: {item.get('status')}")
    from .legacy_rules import auth_observation_lines
    auth_lines.extend(auth_observation_lines(rules.get('auth_evidence') or (result.get('header') or {}).get('auth_evidence') or {}))
    if auth_lines:
        rule_evidence += '\n[인증 상태]\n' + '\n'.join(auth_lines)
    rows = [('기존 규칙', '판정 불가' if failed else '정상',
             '점수 없음' if failed else f"{rules['risk_score']}/100 · 위험 기준 {rules.get('risk_threshold',70)}",
             rule_evidence)]
    razor = engines.get('razor') or {}
    if razor.get('status') == 'ok' and (razor.get('details') or {}).get('catalogue_match') is True:
        rows.append(('Razor 스팸 서명', '탐지', '카탈로그 일치', '공유 스팸 서명과 일치하여 최종 판정에 반영됨'))
    evidence_ml=engines.get('evidence_ml') or {}
    if evidence_ml:
        status=evidence_ml.get('status','missing');details=evidence_ml.get('details') or {};score=evidence_ml.get('score')
        valid=isinstance(score,(int,float)) and not isinstance(score,bool) and math.isfinite(score) and 0<=score<=1
        gate_passed=(details.get('validation_gate') or {}).get('passed') is True
        if status=='ok' and valid and gate_passed:
            used=(result.get('decision') or {}).get('evidence_ml_signal') is True
            rows.append(('구조 증거 ML','정상',f"위험 점수 {score:.3f}",
                         f"모델: {details.get('model_id','설치되지 않음')} · 검증 통과\n"+
                         ('위험 신호를 최종 판정에 반영함' if used else '위험 기준 미만')))
    semantic=engines.get('semantic_ml') or {}
    if semantic:
        status=semantic.get('status','missing');details=semantic.get('details') or {};score=semantic.get('score')
        valid=isinstance(score,(int,float)) and not isinstance(score,bool) and math.isfinite(score) and 0<=score<=1
        decision=result.get('decision') or {}
        if decision.get('semantic_ml_corroborated'):
            semantic_use='문맥 위험 신호가 객관 증거와 일치하여 최종 판정에 반영됨'
        elif details.get('predicted_label')==1:
            semantic_use='위험 문맥 탐지 · 구조 증거와 함께 검토'
        else:
            semantic_use='위험 문맥 기준 미만'
        rows.append(('본문 문맥 ML',STATUS_LABELS.get(status,'알 수 없는 상태'),
                     f"위험 점수 {score:.3f}" if status=='ok' and valid else '판정에 사용할 결과 없음',
                     (f"모델: {details.get('model_id','설치되지 않음')} · 학습 데이터 {details.get('training_rows','?')}건\n역할: 제목·본문의 문맥 위험 신호를 분석하고 구조 증거와 결합\n{semantic_use}") if status=='ok' else semantic.get('error','')))
    html_pair=engines.get('html_pair_ml') or {}
    if html_pair and html_pair.get('status')!='skipped':
        status=html_pair.get('status','missing');details=html_pair.get('details') or {};score=html_pair.get('score')
        pair=details.get('highest_risk_pair') or {}
        valid=isinstance(score,(int,float)) and not isinstance(score,bool) and math.isfinite(score) and 0<=score<=1
        rows.append(('웹페이지 구조 ML',STATUS_LABELS.get(status,'알 수 없는 상태'),
                     f"위험 점수 {score:.3f}" if status=='ok' and valid else '판정에 사용할 결과 없음',
                         (f"모델: {details.get('model_id')} · 검증 기준 통과\n목적지 {pair.get('target_host')} ↔ 공식 {pair.get('reference_host')}\n역할: 실제 수집 페이지와 실시간 검색된 공식 페이지의 구조 차이") if status=='ok' else html_pair.get('error','')))
    decision = result.get('decision') or {}
    review = decision.get('html_review')
    if review is not None:
        names={'external_password_destination':'비밀번호의 외부 호스트 전송 경로','http_password_destination':'비밀번호의 HTTP 전송 경로','password_in_get_request':'비밀번호의 GET 전송 경로'}
        rows.append(('HTML 판정 근거', '검토 필요' if review['signals'] else '검토 신호 없음',
                     f"신호 {len(review['signals'])}개 · 분석 범위 {review['coverage']}",
                     '\n'.join(names[x['kind']]+' · '+str(x.get('target_host')) for x in review['signals']) or '위험한 비밀번호 전송 경로 0건'))
    urls = result.get('url_analysis') or {}
    if 'analyzed_urls' in urls:
        from .link_evidence import hostname
        url_groups = {}
        for item in urls['analyzed_urls']:
            host = hostname(item.get('url', '')) or '호스트 없음'
            sources = tuple(sorted(item.get('sources') or ()))
            score = item.get('risk_score', 0)
            key = (host, sources, score)
            url_groups[key] = url_groups.get(key, 0) + 1
        url_lines = [
            f"{host} · {', '.join(sources) or '출처 없음'} · 규칙 점수 {score} · URL {count}개"
            for (host, sources, score), count in url_groups.items()
        ]
        rows.append(('URL 규칙 검사', '완료',
                     f"주소 {urls.get('total_urls', 0)}개 · 표시 그룹 {len(url_groups)}개",
                     '본문 표시 주소와 HTML href 목적지에 기존 URL 규칙을 적용합니다. 페이지 수집 결과는 목적지 HTML 구조 항목에서 확인합니다.\n' +
                     '\n'.join(url_lines)))
    page = result.get('page_analysis')
    if page is not None:
        details=[]
        for item in page.get('pages', []):
            st=item.get('structure') or {}
            details.append(f"{item.get('requested_host')}: {item['status']} {item.get('reason','')} · 폼 {len(st.get('forms',[]))} · 비밀번호 입력 {st.get('password_fields',0)} · 스크립트 {st.get('script_count',0)} · iframe {st.get('iframe_count',0)}" if item['status']=='ok' else f"{item.get('requested_host')}: {item['status']} {item.get('reason','')}")
            for form in st.get('forms',[]):
                details.append(f"폼 목적지 {form['target_host']} · 외부 호스트 {form['external_host']} · HTTP 전송 {form['insecure_http']}")
            for form in st.get('forms',[]):
                if 'submittable_password_fields' in form:
                    details.append(f"비밀번호 필드: 제출 대상 {form['submittable_password_fields']} · 비활성 {form['disabled_password_fields']} · name 없음 {form['unnamed_password_fields']} · 명시적 CSP 전송 차단 {bool(form['csp_form_action_none_sources'])}")
                    for route in form.get('routes',[])[1:]:
                        details.append(f"버튼별 전송: {route['target_host']} · {route['method']} · 외부 {route['external_host']}")
                    details.append('정적 관측이며 JavaScript에 의한 변경·전송은 평가하지 않았습니다.')
        success=sum(x['status']=='ok' for x in page.get('pages',[]))
        duplicate_note=f" · 동일 호스트 중복 {page.get('duplicate_host_urls',0)}개 정리" if page.get('duplicate_host_urls') else ''
        rows.append(('목적지 HTML 구조', '네트워크 수집 꺼짐' if page['status']=='disabled' else '수집 결과',
                     f"성공 {success}/{len(page.get('pages',[]))} · 한도 제외 {page.get('omitted',0)}개{duplicate_note}",
                     page.get('note','네트워크 비활성화')+'\n'+'\n'.join(details)))
    homepage = result.get('homepage_comparison')
    if homepage is not None:
        lines=[homepage.get('reason',''), homepage.get('note','')]
        for ref in homepage.get('references',[]):
            lines.append(f"{ref['host']} · {'공식 근거 확인' if ref['verified'] else '공식 여부 미확인 후보'} · 수집 {ref['fetch']['status']} {ref['fetch'].get('reason','')} · 근거 {ref.get('source',ref['basis'])}")
        for comparison in homepage.get('comparisons',[]):
            lines.append(
                f"{comparison['target_host']} ↔ {comparison['reference_host']}"
                f" · 구조 유사도 {comparison.get('structure_similarity', comparison.get('tag_count_similarity')):.3f}"
                f" · 태그 유사도 {comparison['tag_count_similarity']:.3f}"
                f" · 비밀번호 입력란 {comparison['password_fields_target']}/{comparison['password_fields_reference']}"
            )
        for mismatch in homepage.get('official_domain_mismatches',[]):
            lines.append(
                f"사칭 도메인 탐지: {mismatch.get('observed_site')} → 공식 {mismatch.get('official_site')}"
                f" · 기관 {mismatch.get('organization')} · 유사도 {mismatch.get('brand_similarity',0):.3f}"
                f" · 실시간 검색 점수 {mismatch.get('discovery_score',0):.3f}"
            )
        rows.append(('공식 홈페이지 비교', {'compared':'비교 완료','disabled':'미실행'}.get(homepage['status'], '기본 분석만' if any(x.get('status') == 'ok' for x in (result.get('page_analysis') or {}).get('pages', [])) else '비교 불가'),
                     f"비교 {len(homepage.get('comparisons',[]))}건 · 사칭 도메인 {homepage.get('official_domain_mismatch_count',0)}건 · 후보 {len(homepage.get('references',[]))}개 · 한도 제외 {homepage.get('omitted',0)}개", '\n'.join(lines)))
    links = result.get('link_evidence')
    if links is not None:
        ok = links.get('status') == 'ok'
        rows.append(('HTML 링크 비교', '정상' if ok else '오류',
                     f"표시·목적지 호스트 불일치 {links.get('different_host_count', 0)}건" if ok else '비교 불가',
                     (links.get('note', '') + '\n' + '\n'.join(
                         f"{x.get('displayed_host')} → {x.get('target_host')} ({x.get('status')})"
                         for x in links.get('links', []))) if ok else links.get('error_type', '분석 오류')))
    reference = result.get('reference_evidence')
    if reference is not None:
        claims = reference.get('claimed_official_links', [])
        relationship_labels={'registered':'등록부 일치','same_sender_domain':'발신자와 동일 기본 도메인',
                             'unregistered':'등록 관계 없음','unresolved':'호스트 없음'}
        claim_lines = '\n'.join(
            f"{x.get('organization')} 공식 링크 주장 → {x.get('target_host')} ({x.get('relationship')})"
            for x in claims
        )
        rows.append(('발신·링크 도메인 관계', '분석 완료' if reference.get('status') == 'dynamic' else reference.get('status', 'unknown'),
                     f"관측 호스트 {len(reference.get('domain_relationships', []))}개",
                     reference.get('note', '') + '\n' +
                     f"From/Reply-To: {reference.get('from_reply_relation', 'not_observed')}\n" +
                     '\n'.join(f"{x.get('host')} : {relationship_labels.get(x.get('relationship'),x.get('relationship'))}" for x in reference.get('domain_relationships', [])) +
                     ('\n' + claim_lines if claim_lines else '')))
        if reference.get('template_status') == 'compared' and reference.get('template_comparisons'):
            rows.append(('정상 이메일 템플릿', '비교 완료',
                         f"비교 {len(reference.get('template_comparisons', []))}건",
                         '\n'.join(f"{x.get('template_id')}: 태그 구성 유사도 {x.get('tag_count_similarity')}" for x in reference.get('template_comparisons', []))))
        if reference.get('forms'):
            rows.append(('HTML 폼 목적지', '관측', f"폼 {len(reference['forms'])}개",
                         '\n'.join(f"{x.get('host')} ({x.get('status')})" for x in reference['forms'])))
    return [tuple(presentation_text(str(v)) for v in row) for row in rows]


def decision_text(result):
    decision = result.get('decision') or {}
    return presentation_text('\n'.join(decision.get('reasons') or ['ML·Razor는 참고 근거이며 기존 판정을 자동 변경하지 않습니다.']))


def inconclusive_explanation(result):
    rules = result.get('rule_result') or result
    auth = rules.get('auth_summary') or {}
    reasons = []
    if auth.get('incomplete'):
        reasons.append('인증 근거 누락: 송신 IP·서명·정렬 결과는 헤더 실행 결과를 확인하세요.')
    if (result.get('decision') or {}).get('unavailable_engines'):
        reasons.append('일부 엔진 실행 실패: ' + ', '.join((result.get('decision') or {}).get('unavailable_engines', [])))
    page = result.get('page_analysis') or {}
    failed = [str(x.get('requested_host', 'URL')) + ': ' + str(x.get('reason', x.get('status'))) for x in page.get('pages', []) if x.get('status') != 'ok']
    if failed: reasons.append('페이지 수집 실패: ' + '; '.join(failed))
    if page.get('omitted'): reasons.append('수집 한도 초과: ' + str(page['omitted']) + '건')
    return ' '.join(reasons) or '판정에 필요한 분석 결과가 없습니다.'


def presentation_text(text):
    replacements = {
        '실제 피싱 확률로 보정되지 않은 참고 점수':'학습 데이터 분류 점수 · 최종 판정 계산에서 제외',
        '스팸 서명 카탈로그 조회 결과이며, 미일치는 안전하다는 뜻이 아닙니다.':'스팸 서명 카탈로그 조회 결과',
        '안전 확정이 아닙니다. 인증 및 분석 범위를 별도로 확인하세요.':'HTML 전송 경로 검토 신호 0건',
        '정적 HTML만 분석. 스크립트·폼 제출·하위 리소스 실행 없음. 관측은 악성 확정이나 공식 사이트 비교 결과가 아닙니다.':'응답 HTML 분석. JavaScript 실행·폼 제출·하위 리소스 요청 없음.',
        '공식 근거와 수집 성공이 모두 있는 경우에만 비교합니다. 후보 접속 성공은 공식성 증명이 아닙니다. 기본 구조 결과는 유지합니다.':'출처가 등록된 기준 페이지와 수집에 성공한 목적지 페이지를 비교합니다.',
        '웹페이지끼리 태그 개수 구성을 비교한 참고 수치입니다. 화면·동작의 동일성 또는 안전성 점수가 아니며 홈페이지와 하위 페이지의 차이도 반영됩니다.':'유사도: 태그별 개수의 교집합/합집합. 전송 목적지는 별도로 검사합니다.',
        '문자열 관측입니다. 불일치는 위탁·추적 링크일 수도 있으며, 일치는 안전·기관 소유의 증명이 아닙니다. 네트워크 접속 없음.':'표시 주소와 href 목적지의 호스트를 비교합니다.',
        '발신 주소는 주장값입니다. 도메인 등록·HTML 유사도는 인증 성공 또는 안전 판정이 아닙니다. 미등록은 악성의 증거가 아닙니다.':'등록부에 기록된 기관·도메인 연결 관계를 조회합니다.',
        '동일 매체(email_html)만 비교. 구조 유사도는 안전 판정이 아닙니다. 적합한 근거가 없으면 비교하지 않습니다.':'등록된 이메일 HTML 템플릿만 비교합니다.',
        '선택 NLP 기능은 미설치/비활성 상태를 안전 근거로 사용하지 않습니다.':'본문 기관명 추출 기능 실행 상태',
        '정보 부족: unverified_pass':'판정 제외: 원문 pass의 발행 출처 확인 자료 없음',
        '미검증':'판정 제외',
        '정보 부족: unknown':'판정 제외: 원본 인증 정보 없음',
    }
    for old,new in replacements.items():text=text.replace(old,new)
    return text
