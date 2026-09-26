import unittest

from main_gui import build_analysis_summary


class GuiSummaryTests(unittest.TestCase):
    def test_summary_contains_only_reflected_decision_evidence(self):
        result = {
            'verdict': 'suspicious', 'session_path': 'email8_test',
            'header': {'spf_check': 'unverified_pass', 'dnssec_status': 'signed',
                       'details': {'dns_queries': [{'domain': 'example.org', 'type': 'A', 'status': 'ok'}]}},
            'decision': {'signals': [
                {'reflected': True, 'summary': '유사 사칭 도메인: p0lice.kr → police.go.kr'},
                {'reflected': False, 'summary': '참고 ML 신호'},
            ]},
        }
        summary = build_analysis_summary(result)
        self.assertIn('유사 사칭 도메인', summary)
        self.assertIn('[발신자 기관 유형] ℹ️ 확인되지 않음', summary)
        for diagnostic in ('SPF', 'DNSSEC', 'DNS 조회', '참고 ML 신호', '규칙 진단 점수'):
            self.assertNotIn(diagnostic, summary)

    def test_summary_includes_sender_organization_type(self):
        result = {
            'verdict': 'no_signal',
            'session_path': 'notion_test',
            'header': {
                'organization_type': 'technology',
                'organization_subtype': 'it_software',
            },
            'decision': {'signals': []},
        }
        summary = build_analysis_summary(result)
        self.assertIn('[발신자 기관 유형] 💻 technology/it_software', summary)

    def test_attachment_summary_distinguishes_clean_and_threat(self):
        result = {'verdict': 'dangerous', 'session_path': 'attachment_test',
                  'decision': {'signals': []}, 'attachments': [
                      {'filename': 'photo.jpg', 'malware_scan': {'status': 'clean'}},
                      {'filename': 'payload.bin', 'malware_scan': {
                          'status': 'threat_detected', 'threat_name': 'Test.Signature'}},
                  ]}
        summary = build_analysis_summary(result)
        self.assertIn('photo.jpg: 위험 신호 없음', summary)
        self.assertIn('payload.bin: 악성코드 탐지', summary)
        self.assertIn('탐지명: Test.Signature', summary)


if __name__ == '__main__':
    unittest.main()
