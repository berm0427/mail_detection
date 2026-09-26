import unittest
from unittest.mock import patch
from email.message import EmailMessage

from email_analyzer.homepage_comparison import compare_homepages


class HomepageTests(unittest.TestCase):
    def setUp(self):
        self.message = EmailMessage(); self.message['From'] = 'Example Team <x@example.com>'
        self.target = {'status': 'ok', 'requested_host': 'login.other.test',
                       'structure': {'tag_counts': {'html': 1, 'form': 1}, 'password_fields': 1,
                                     'forms': [{}], 'input_count': 1}}
        self.reference = {'status': 'ok', 'requested_host': 'example.com',
                          'hops': [{'host': 'example.com'}],
                          'structure': {'tag_counts': {'html': 1, 'form': 1}, 'password_fields': 1,
                                        'forms': [{}], 'input_count': 1}}
        self.discovery = {'status': 'ranked', 'queries': ['Example'], 'candidates': [{
            'host': 'example.com', 'url': 'https://example.com/', 'source': 'wikidata_p856',
            'label': 'Example', 'entity_id': 'Q1', 'ml_score': .81}]}

    def run_case(self, reference=None, target=None, discovery=None):
        with patch('email_analyzer.homepage_comparison.discover_official_sites',
                   return_value=discovery if discovery is not None else self.discovery), \
             patch('email_analyzer.homepage_comparison.analyze_pages',
                   return_value={'pages': [reference if reference is not None else self.reference]}):
            return compare_homepages(self.message, {'pages': [target if target is not None else self.target]},
                                     {'links': []}, semantic_model_path='model.json')

    def test_ml_ranked_candidate_is_compared(self):
        result = self.run_case()
        self.assertEqual(result['status'], 'compared')
        self.assertEqual(result['comparisons'][0]['tag_count_similarity'], 1)
        self.assertEqual(result['references'][0]['basis'], 'live_entity_search_ml_ranked')

    def test_no_dynamic_candidate_is_basic_only(self):
        result = self.run_case(discovery={'status': 'no_candidates', 'queries': ['x'], 'candidates': []})
        self.assertEqual(result['status'], 'basic_only'); self.assertEqual(result['references'], [])

    def test_fetch_failure_is_basic_only(self):
        self.assertEqual(self.run_case(reference={'status': 'error'})['status'], 'basic_only')

    def test_cross_site_redirect_loses_verification(self):
        reference = {**self.reference, 'hops': [{'host': 'outside.test'}]}
        self.assertEqual(self.run_case(reference=reference)['status'], 'basic_only')

    def test_disabled_does_not_search_or_fetch(self):
        with patch('email_analyzer.homepage_comparison.discover_official_sites') as discover, \
             patch('email_analyzer.homepage_comparison.analyze_pages') as fetch:
            result = compare_homepages(self.message, {}, {}, disabled=True)
        self.assertEqual(result['status'], 'disabled'); discover.assert_not_called(); fetch.assert_not_called()

    def test_unrelated_noninteractive_page_is_not_compared(self):
        target = {**self.target, 'structure': {'tag_counts': {'meta': 1}, 'element_count': 1,
                                                'input_count': 0, 'forms': [], 'password_fields': 0}}
        result = self.run_case(target=target)
        self.assertEqual(result['status'], 'basic_only'); self.assertEqual(result['comparisons'], [])

    def test_live_official_candidate_detects_confusable_sender_without_fetch(self):
        message = EmailMessage(); message['From'] = '경찰청 <notice@p0lice.kr>'
        discovery={'status':'ranked','queries':['경찰청'],'candidates':[{
            'host':'www.police.go.kr','url':'https://www.police.go.kr/','source':'wikidata_p856',
            'label':'대한민국 경찰청','entity_id':'Q1','ml_score':.3,'ranking_score':.54}]}
        with patch('email_analyzer.homepage_comparison.discover_official_sites', return_value=discovery), \
             patch('email_analyzer.homepage_comparison.analyze_pages', return_value={'pages':[{'status':'error'}]}):
            result=compare_homepages(message,{'pages':[]},{'links':[]},semantic_model_path='model.json')
        self.assertEqual(result['official_domain_mismatch_count'],1)
        self.assertEqual(result['official_domain_mismatches'][0]['observed_site'],'p0lice.kr')

    def test_delivery_subdomain_is_not_a_domain_mismatch(self):
        discovery={**self.discovery,'candidates':[{**self.discovery['candidates'][0],
                    'host':'notion.so','url':'https://notion.so','label':'Notion','ranking_score':.8}]}
        message=EmailMessage();message['From']='Notion <notify@mail.notion.so>'
        with patch('email_analyzer.homepage_comparison.discover_official_sites',return_value=discovery), \
             patch('email_analyzer.homepage_comparison.analyze_pages',return_value={'pages':[{'status':'error'}]}):
            result=compare_homepages(message,{'pages':[]},{'links':[]},semantic_model_path='model.json')
        self.assertEqual(result['official_domain_mismatch_count'],0)


if __name__ == '__main__': unittest.main()
