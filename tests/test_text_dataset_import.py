import unittest
from email import policy
from email.parser import BytesParser

from email_analyzer.evidence_features import message_text
from email_analyzer.mail_identity import mail_digest
from tools.evaluate_semantic_external import summarize
from tools.import_text_dataset import build_eml, convert_rows

OPTIONS = dict(source="sample-set", text_field="text", title_field="title", label_field="type",
               positive={"spam"}, negative={"not spam"}, label_definition="spam")


class TextDatasetImportTests(unittest.TestCase):
    def test_rows_become_minimal_mails_without_label_or_source_headers(self):
        rows = [{"title": "계정 확인", "text": "링크를 눌러 본인인증을 완료하세요.", "type": "spam"},
                {"title": "회의 안내", "text": "내일 오전 회의가 있습니다.", "type": "not spam"}]
        items, report = convert_rows(rows, **OPTIONS)
        self.assertEqual([item["row"]["label"] for item in items], [1, 0])
        self.assertEqual(report["labels"], {"0": 1, "1": 1})
        message = BytesParser(policy=policy.default).parsebytes(items[0]["raw"])
        self.assertIn("본인인증", message_text(message))
        self.assertIn("계정 확인", message_text(message))
        header_names = {name.lower() for name in message.keys()}
        self.assertFalse({name for name in header_names if name.startswith(("x-dataset", "x-synthetic"))})
        self.assertNotIn(b"spam", items[0]["raw"].lower())
        self.assertNotIn(b"sample-set", items[0]["raw"])
        self.assertEqual(items[0]["row"]["sha256"], mail_digest(items[0]["raw"]))
        self.assertTrue(items[0]["row"]["text_only"])
        self.assertEqual(items[0]["row"]["label_definition"], "spam")

    def test_exact_duplicates_and_empty_rows_are_skipped(self):
        rows = [{"title": "a", "text": "same", "type": "spam"}, {"title": "a", "text": "same", "type": "spam"},
                {"title": "", "text": "  ", "type": "not spam"}, {"title": "b", "text": "other", "type": "not spam"}]
        items, report = convert_rows(rows, **OPTIONS)
        self.assertEqual(len(items), 2)
        self.assertEqual((report["exact_duplicates_skipped"], report["empty_skipped"]), (1, 1))
        self.assertEqual(len({item["row"]["eml"] for item in items}), 2)

    def test_text_with_contradictory_labels_is_dropped_entirely(self):
        rows = [{"title": "a", "text": "same", "type": "spam"}, {"title": "k", "text": "keep", "type": "not spam"},
                {"title": "a", "text": "same", "type": "not spam"}, {"title": "z", "text": "last", "type": "spam"}]
        items, report = convert_rows(rows, **OPTIONS)
        self.assertEqual(report["conflicting_label_texts_dropped"], 1)
        self.assertEqual([item["row"]["label"] for item in items], [0, 1])
        self.assertEqual([item["row"]["eml"] for item in items], ["sample-set-000001.eml", "sample-set-000002.eml"])
        self.assertNotIn(b"same", b"".join(item["raw"] for item in items))

    def test_each_row_is_its_own_group_unless_a_group_field_is_given(self):
        rows = [{"title": "a", "text": "one", "type": "spam", "campaign": "c1"},
                {"title": "b", "text": "two", "type": "spam", "campaign": "c1"}]
        own, _ = convert_rows(rows, **OPTIONS)
        self.assertEqual(len({item["row"]["group_id"] for item in own}), 2)
        grouped, report = convert_rows(rows, **OPTIONS, group_field="campaign")
        self.assertEqual({item["row"]["group_id"] for item in grouped}, {"sample-set:c1"})
        self.assertEqual(report["groups"], 1)

    def test_unknown_label_values_and_bad_options_are_rejected(self):
        with self.assertRaises(ValueError):
            convert_rows([{"title": "a", "text": "x", "type": "maybe"}], **OPTIONS)
        with self.assertRaises(ValueError):
            convert_rows([], **{**OPTIONS, "source": "Bad Name"})
        with self.assertRaises(ValueError):
            convert_rows([], **{**OPTIONS, "negative": {"spam"}})

    def test_title_newlines_cannot_inject_headers(self):
        raw = build_eml("line one\r\nX-Dataset-Label: phishing", "body")
        message = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertIsNone(message.get("X-Dataset-Label"))

    def test_external_summary_counts_unscored_separately(self):
        counts = summarize([(1, 1), (1, 0), (0, 0), (0, None)])
        self.assertEqual((counts["tp"], counts["fn"], counts["tn"], counts["unscored"]), (1, 1, 1, 1))
        self.assertEqual(counts["accuracy_of_scored"], round(2 / 3, 4))
        self.assertIsNone(summarize([(1, None)])["accuracy_of_scored"])


if __name__ == "__main__":
    unittest.main()
