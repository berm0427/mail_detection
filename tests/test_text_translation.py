import unittest
from unittest.mock import patch

from email_analyzer.text_translation import detect_text_language, translate_context_to_korean


class TextTranslationTests(unittest.TestCase):
    def test_language_detection_distinguishes_korean_and_english(self):
        self.assertEqual(detect_text_language('계정 보안 안내를 확인해 주시기 바랍니다.'), 'ko')
        self.assertEqual(detect_text_language('Please review the attached account security notice.'), 'en')

    def test_korean_does_not_load_translation_model(self):
        with patch('email_analyzer.text_translation.preload_translation_model') as loader:
            result = translate_context_to_korean('계정 보안 안내를 확인해 주시기 바랍니다.', 'missing')
        self.assertEqual(result['status'], 'not_required')
        self.assertFalse(result['translated'])
        loader.assert_not_called()

    def test_missing_model_keeps_original_foreign_text(self):
        text = 'Please review the attached account security notice.'
        result = translate_context_to_korean(text, None)
        self.assertEqual(result['status'], 'model_unavailable')
        self.assertEqual(result['text'], text)

    def test_machine_addresses_are_removed_before_translation(self):
        from email_analyzer.text_translation import _mask_machine_tokens
        masked = _mask_machine_tokens('Open https://evil.example/a and mail user@example.org now')
        self.assertNotIn('evil.example', masked)
        self.assertNotIn('user@example.org', masked)
        self.assertEqual(masked.count('[LINK]'), 2)


if __name__ == '__main__':
    unittest.main()
