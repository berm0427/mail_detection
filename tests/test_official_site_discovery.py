import unittest
from email.message import EmailMessage
from unittest.mock import patch
import numpy as np

from email_analyzer.official_site_discovery import discover_official_sites, search_terms


class FakeEncoder:
    def encode(self, texts, **kwargs):
        return np.asarray([[1., 0.], [.9, .1], [.1, .9]][:len(texts)])


class DiscoveryTests(unittest.TestCase):
    def message(self):
        msg = EmailMessage(); msg['From'] = '경찰청 교통민원24 <noreply@p0lice.kr>'
        msg['Subject'] = '과태료 안내'; msg.set_content('경찰청 공식 안내를 확인하세요.'); return msg

    def test_terms_use_display_domain_and_subject(self):
        terms = search_terms(self.message())
        self.assertIn('경찰청 교통민원24', terms); self.assertIn('p0lice', terms)

    @patch('email_analyzer.official_site_discovery.preload_semantic_encoder', return_value=FakeEncoder())
    @patch('email_analyzer.official_site_discovery._api')
    def test_live_candidates_are_ranked_by_local_ml(self, api, encoder):
        entity = {
            'labels': {'ko': {'value': '경찰청'}},
            'descriptions': {'ko': {'value': '대한민국 경찰 기관'}},
            'claims': {'P856': [{
                'rank': 'normal',
                'mainsnak': {'datavalue': {'value': 'https://www.police.go.kr/'}},
            }]},
        }
        def response(params, timeout):
            if params['action'] == 'wbgetentities': return {'entities': {'Q1': entity}}
            return {'search': [{'id': 'Q1'}]} if '경찰청' in params['search'] else {'search': []}
        api.side_effect = response
        result = discover_official_sites(self.message(), 'semantic.json')
        self.assertEqual(result['status'], 'ranked')
        self.assertEqual(result['candidates'][0]['host'], 'www.police.go.kr')
        self.assertEqual(result['ranking_model'], 'local_minilm_hybrid_ranker')

    def test_disabled_makes_no_network_call(self):
        with patch('email_analyzer.official_site_discovery._api') as api:
            result = discover_official_sites(self.message(), 'x', disabled=True)
        self.assertEqual(result['status'], 'disabled'); api.assert_not_called()


if __name__ == '__main__': unittest.main()
