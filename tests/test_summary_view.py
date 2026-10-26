import unittest

from email_analyzer.decision import combine_evidence
from main_gui import build_analysis_summary


def analysed(semantic=0.0, threat=False, **extra):
    """Run the real decision policy so the summary is tested against its output."""
    result = {
        "verdict": "suspicious", "session_path": "s",
        "engine_results": {"semantic_ml": {"status": "ok", "score": semantic},
                           "razor": {"status": "ok", "details": {"catalogue_match": False}}},
        "attachments": [{"malware_scan": {"status": "threat_detected" if threat else "clean"}}],
        "rule_result": {"auth_summary": {}}, "reference_evidence": {}, "link_evidence": {},
        "page_analysis": {"status": "disabled", "pages": []},
    }
    result.update(extra)
    result["decision"] = combine_evidence(result)
    result["verdict"] = result["decision"]["verdict"]
    return result


class SummaryViewTests(unittest.TestCase):
    def test_ml_negative_with_antivirus_report_is_review_not_no_signal(self):
        summary = build_analysis_summary(analysed(semantic=0.0, threat=True))
        self.assertIn("[종합 상태] 🔎 검토 필요", summary)
        self.assertIn("[최종 ML 판정] 위험 문맥 기준 미만", summary)
        self.assertIn("[검토 필요 관측 · 판정에 자동 반영되지 않음]", summary)
        self.assertIn("첨부파일 백신 엔진 위협 보고 1건", summary)
        self.assertNotIn("탐지된 위험 신호 없음", summary)

    def test_official_route_alone_requests_review(self):
        summary = build_analysis_summary(analysed(homepage_comparison={"official_external_action_routes": [
            {"organization": "경찰청", "target_host": "unrelated.example"}]}))
        self.assertIn("[종합 상태] 🔎 검토 필요", summary)
        self.assertIn("경찰청 → unrelated.example", summary)

    def test_clean_ml_negative_says_no_signal_without_observation_section(self):
        summary = build_analysis_summary(analysed(semantic=0.0))
        self.assertIn("[종합 상태] ℹ️ 탐지된 위험 신호 없음", summary)
        self.assertIn("[최종 ML 판정] 위험 문맥 기준 미만", summary)
        self.assertNotIn("[검토 필요 관측", summary)
        self.assertNotIn("본문 문맥 위험 점수", summary)

    def test_ml_positive_is_caution(self):
        summary = build_analysis_summary(analysed(semantic=0.99))
        self.assertIn("[종합 상태] ⚠️ 주의", summary)
        self.assertIn("[최종 ML 판정] 위험 문맥 기준 이상", summary)

    def test_unavailable_ml_is_shown_as_not_computable(self):
        result = analysed()
        result["engine_results"]["semantic_ml"] = {"status": "error"}
        result["decision"] = combine_evidence(result)
        result["verdict"] = result["decision"]["verdict"]
        summary = build_analysis_summary(result)
        self.assertIn("[종합 상태] ❔ 판정 불가", summary)
        self.assertIn("[최종 ML 판정] 계산 불가", summary)

    def test_engine_table_separates_ml_verdict_from_review_observations(self):
        from email_analyzer.engine_view import engine_rows
        top = engine_rows(analysed(semantic=0.0, threat=True))[0]
        self.assertEqual(top[0], "통합 판정")
        self.assertIn("검토 필요 · ML 판정 기준 미만 · 검토 관측 1건", top[2])
        self.assertIn("ML 판정 · ML 판정 위험 확률", top[3])
        self.assertIn("ML 입력 · 본문 문맥 위험 점수", top[3])
        self.assertIn("검토 관측 · 첨부파일 백신 엔진 위협 보고 1건", top[3])
        self.assertNotIn("검토 관측 · ML 판정", top[3])

    def test_saved_result_without_overall_status_still_requests_review(self):
        legacy = {"verdict": "no_signal", "session_path": "s", "decision": {"signals": [
            {"id": "attachment_antivirus_report", "reflected": False, "summary": "첨부파일 백신 엔진 위협 보고 1건"}]}}
        self.assertIn("[종합 상태] 🔎 검토 필요", build_analysis_summary(legacy))


if __name__ == "__main__":
    unittest.main()
