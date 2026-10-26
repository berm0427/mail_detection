import unittest

from main_gui import build_analysis_summary


class SummaryViewTests(unittest.TestCase):
    def test_reference_signals_are_listed_separately_from_verdict_basis(self):
        result = {"verdict": "no_signal", "session_path": "s", "decision": {"signals": [
            {"id": "ml_verdict", "reflected": False, "summary": "ML 판정 위험 확률 0.147 (기준 0.50)"},
            {"id": "official_claim_external_route", "reflected": False,
             "summary": "기관 주장과 무관한 클릭 경로: 경찰청 → unrelated.example"},
            {"id": "semantic_ml_score", "reflected": False, "summary": "본문 문맥 위험 점수 0.000"},
        ]}}
        summary = build_analysis_summary(result)
        self.assertIn("판정에 반영된 위험 신호가 없습니다.", summary)
        self.assertIn("[참고 신호 · 판정에 반영되지 않음]", summary)
        self.assertIn("경찰청 → unrelated.example", summary)
        self.assertNotIn("본문 문맥 위험 점수", summary)

    def test_reflected_signals_are_not_repeated_as_reference(self):
        result = {"verdict": "suspicious", "session_path": "s", "decision": {"signals": [
            {"id": "ml_verdict", "reflected": True, "summary": "ML 판정 위험 확률 0.988 (기준 0.50)"},
        ]}}
        summary = build_analysis_summary(result)
        self.assertIn("[판정 근거]", summary)
        self.assertNotIn("[참고 신호", summary)


if __name__ == "__main__":
    unittest.main()
