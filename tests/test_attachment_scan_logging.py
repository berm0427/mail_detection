import unittest

from email_analyzer.integration import log_attachment_scan_result


class AttachmentScanLoggingTests(unittest.TestCase):
    def test_logs_each_scanner_layer_and_final_result(self):
        scan = {
            'status': 'clean',
            'static_findings': [],
            'clamav': {'status': 'clean'},
            'external_scan_status': 'disabled',
        }
        with self.assertLogs('email_analyzer.integration', level='INFO') as captured:
            log_attachment_scan_result('leaflet.jpg', scan)
        output = '\n'.join(captured.output)
        self.assertIn('악성코드 검사: leaflet.jpg', output)
        self.assertIn('내부 정적 검사: 이상 없음', output)
        self.assertIn('ClamAV: 위험 신호 없음', output)
        self.assertIn('Microsoft Defender: 비활성', output)
        self.assertIn('최종 결과: 위험 신호 없음', output)


if __name__ == '__main__':
    unittest.main()
