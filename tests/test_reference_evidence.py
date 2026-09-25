import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from datetime import date,timedelta
from email.message import EmailMessage
from unittest.mock import Mock,AsyncMock
from email_analyzer.reference_evidence import analyze_references,load_registry,registrable_domain


class ReferenceTests(unittest.TestCase):
    def test_registrable_domain_handles_subdomains(self):
        self.assertEqual(registrable_domain('mail.notion.so'),'notion.so')
        self.assertEqual(registrable_domain('www.notion.so'),'notion.so')

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.path=self.root/'registry.json'
        self.html='<p>Notice</p><a href="https://service.example/login">https://service.example/login</a>'
        (self.root/'template.html').write_text(self.html,encoding='utf-8')
        today=date.today()
        self.proof={'status':'verified','source':'test-only synthetic provenance','verified_at':today.isoformat(),'review_due':(today+timedelta(days=30)).isoformat()}
        self.data={'schema_version':1,'domains':[dict(self.proof,organization='Demo',aliases=['데모 은행'],domain='sender.example',role='official'),dict(self.proof,organization='Demo',domain='service.example',role='delegated_link')],
                   'templates':[dict(self.proof,id='synthetic',organization='Demo',kind='email_html',file='template.html',sha256=hashlib.sha256(self.html.encode()).hexdigest())]}
        self.save()
    def save(self):self.path.write_text(json.dumps(self.data),encoding='utf-8')
    def msg(self,sender='a@sender.example',html=None):
        m=EmailMessage();m['From']=sender;m.set_content(html or self.html,subtype='html');return m
    def test_registered_relationship_is_not_authentication(self):
        r=analyze_references(self.msg(),self.path)
        self.assertEqual(r['domain_relationships'][0]['relationship'],'registered')
        self.assertFalse(r['sender_authenticated']);self.assertNotIn('risk_score',r)
    def test_unregistered_sibling_subdomains_show_sender_domain_relation(self):
        message=self.msg('notice@mail.notion.so','<a href="https://www.notion.so/page">open</a><img src="https://www.notion.so/image">')
        r=analyze_references(message,self.path)
        self.assertEqual(r['registered_domains'],0)
        self.assertEqual(len(r['domain_relationships']),1)
        self.assertEqual(r['domain_relationships'][0]['relationship'],'same_sender_domain')
        self.assertEqual(r['domain_relationships'][0]['registrable_domain'],'notion.so')
        self.assertEqual(r['domain_relationships'][0]['tags'],['a','img'])
    def test_same_medium_comparison(self):
        r=analyze_references(self.msg(),self.path)
        self.assertEqual(r['template_status'],'compared')
        self.assertEqual(r['template_comparisons'][0]['tag_count_similarity'],1)
    def test_website_is_not_email_template(self):
        self.data['templates'][0]['kind']='website_html';self.save()
        self.assertEqual(analyze_references(self.msg(),self.path)['template_status'],'no_eligible_reference')
    def test_tampered_template_rejected(self):
        (self.root/'template.html').write_text('<form/>',encoding='utf-8')
        self.assertEqual(analyze_references(self.msg(),self.path)['template_status'],'no_eligible_reference')
    def test_unreviewed_and_expired_reference_rejected(self):
        self.data['domains'][0]['review_due']='2000-01-01';self.data['domains'][1]['status']='candidate';self.save()
        self.assertEqual(load_registry(self.path)['domains'],[])
    def test_suffix_attack_and_multiple_sender(self):
        for sender in ['a@sender.example.evil.example','a@sender.example, b@evil.example']:
            self.assertEqual(analyze_references(self.msg(sender),self.path)['sender_organizations_observed'],[])
    def test_template_path_outside_root_rejected(self):
        self.data['templates'][0]['file']='../outside.html';self.save()
        self.assertEqual(analyze_references(self.msg(),self.path)['template_status'],'no_eligible_reference')
    def test_absent_registry_and_html_ml_abstain(self):
        r=analyze_references(self.msg(),self.root/'missing.json')
        self.assertEqual(r['status'],'missing');self.assertEqual(r['ml']['status'],'not_applied')
    def test_external_form_and_reply_are_observations(self):
        m=self.msg(html='<form action="https://other.example/send"><input name="password"></form>');m['Reply-To']='b@other.example'
        r=analyze_references(m,self.path)
        self.assertEqual(r['forms'][0]['host'],'other.example');self.assertEqual(r['from_reply_relation'],'different_hosts');self.assertNotIn('verdict',r)
    def test_copied_template_does_not_authenticate_sender(self):
        r=analyze_references(self.msg(),self.path)
        self.assertEqual(r['template_comparisons'][0]['tag_count_similarity'],1)
        self.assertFalse(r['sender_authenticated'])
    def test_explicit_official_claim_must_use_registered_link(self):
        good=analyze_references(self.msg(html='<a href="https://service.example/login">데모 은행 공식 로그인</a>'),self.path)
        bad=analyze_references(self.msg(html='<a href="https://dem0.example/login">데모 은행 공식 로그인</a>'),self.path)
        self.assertEqual(good['official_claim_mismatch_count'],0)
        self.assertEqual(good['claimed_official_links'][0]['relationship'],'registered')
        self.assertEqual(bad['official_claim_mismatch_count'],1)
        self.assertEqual(bad['claimed_official_links'][0]['target_host'],'dem0.example')
    def test_brand_mention_without_official_claim_does_not_trigger(self):
        r=analyze_references(self.msg(html='<a href="https://other.example">데모 은행 관련 기사</a>'),self.path)
        self.assertEqual(r['official_claim_mismatch_count'],0)
    def test_legacy_brand_search_is_retired(self):
        from email_analyzer.integration import IntegratedAnalyzer
        self.assertFalse(hasattr(IntegratedAnalyzer, 'analyze_brand_matching'))
    def test_remote_ai_scoring_is_retired(self):
        from email_analyzer.integration import IntegratedAnalyzer
        self.assertFalse(hasattr(IntegratedAnalyzer, 'analyze_with_multi_ai'))
