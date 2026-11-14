import hashlib
import json
import os
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from email_analyzer.mail_identity import combined_digest, mail_digest, strip_label_headers
from email_analyzer.ml_verdict import SchemaMismatchError, analyze_ml_verdict
from email_analyzer.ml_verdict_features import FEATURE_NAMES, SCHEMA_VERSION, ml_verdict_feature_dict
from tools.extract_synthetic_evidence import (MODES, _engine_observations, check_saved_analysis,
                                              reuse_saved_analysis, slim)
from tools.label_real_mail import append_row, build_row, parse_observation_labels
import tools.promote_ml_verdict as promote_module
from tools.promote_ml_verdict import (check_disjoint, check_install_targets_free, count_outcomes,
                                      holdout_identity, install, install_targets, promotion_decision)
from tools.retrain_ml_verdict import serving_text
from tools.split_holdout import check_no_shared_mail, in_holdout, split_rows
from tools.train_ml_verdict import training_data_limitation, verify_evidence_binding


def live_result():
    return {
        "verdict": "suspicious", "metadata": {"Subject": "s"},
        "engine_results": {
            "semantic_ml": {"status": "ok", "score": 0.9},
            "razor": {"status": "ok", "details": {"catalogue_match": True, "raw": "x"}},
            "html_pair_ml": {"status": "ok", "score": 0.7, "details": {
                "predicted_label": 1, "validation_gate": {"passed": True}, "highest_risk_pair": {}}},
        },
        "rule_result": {"auth_summary": {"failures": [{"method": "DKIM"}]}},
        "reference_evidence": {"official_claim_mismatch_count": 1},
        "link_evidence": {}, "page_analysis": {"status": "complete", "pages": []},
        "attachments": [{"malware_scan": {"status": "threat_detected", "threat_name": "x"}}],
    }


MAIL = b"Message-ID: <one@example>\r\nDate: Mon, 1 Jan 2026 00:00:00 +0900\r\nSubject: s\r\n\r\nbody"


def saved_result():
    result = live_result()
    result["ml_feature_schema"] = SCHEMA_VERSION
    result["eml_sha256"] = mail_digest(MAIL)
    result["metadata"] = {"Message-ID": "<one@example>", "Date": "Mon, 1 Jan 2026 00:00:00 +0900", "Subject": "s"}
    return result


class ExtractionTests(unittest.TestCase):
    def test_live_mode_keeps_network_scanners_and_razor_enabled(self):
        self.assertTrue(MODES["offline"]["disable_network"])
        self.assertNotIn("disable_network", MODES["live"])
        self.assertNotIn("disable_attachment_scan", MODES["live"])
        self.assertNotIn("razor_command", MODES["live"]["engine_config_override"])
        # The semantic score is always replaced by an out-of-fold prediction.
        self.assertEqual(MODES["live"]["engine_config_override"]["semantic_ml_model"], "")

    def test_slim_keeps_engine_observations_but_never_the_semantic_score(self):
        kept = _engine_observations(live_result())
        self.assertEqual(set(kept), {"razor", "html_pair_ml"})
        self.assertEqual(kept["razor"]["details"], {"catalogue_match": True})

    def test_live_observations_survive_slimming_as_ml_features(self):
        features = ml_verdict_feature_dict(slim(live_result()))
        for name in ("razor_catalogue_match", "html_pair_available", "authentication_failure_count",
                     "official_claim_mismatch_count", "attachment_threat_count"):
            self.assertGreater(features[name], 0, name)
        self.assertEqual(features["html_pair_score"], 0.7)
        self.assertEqual(features["semantic_available"], 0.0)

    def test_saved_analysis_is_reused_and_bound_to_the_mail(self):
        with tempfile.TemporaryDirectory() as folder:
            eml = Path(folder) / "mail.eml"
            eml.write_bytes(MAIL)
            saved = Path(folder) / "final_analysis_result.json"
            saved.write_text(json.dumps(saved_result()), encoding="utf-8")
            row = {"eml": str(eml), "label": 1, "split": "train", "group_id": "g", "analysis_result": str(saved)}
            evidence = reuse_saved_analysis(row)
            self.assertEqual(evidence["extraction_mode"], "saved_live")
            self.assertEqual(evidence["eml_sha256"], mail_digest(MAIL))
            self.assertEqual(evidence["analysis"]["rule_result"]["auth_summary"]["failures"], [{"method": "DKIM"}])

    def test_saved_analysis_is_rejected_when_it_cannot_be_trusted(self):
        def changed(**updates):
            result = saved_result()
            result.update(updates)
            return result
        # Same Message-ID and Date but a different body: a campaign sibling, not this mail.
        other_mail = saved_result()
        other_mail["eml_sha256"] = mail_digest(MAIL.replace(b"body", b"another body"))
        leaking = saved_result()
        leaking["metadata"]["X-Dataset-Label"] = "phishing"
        unmatched = saved_result()
        del unmatched["eml_sha256"]
        for name, result in (("old feature schema", changed(ml_feature_schema="ml-verdict-features-v0")),
                             ("unstamped", changed(ml_feature_schema=None)),
                             ("error result", changed(verdict="error")),
                             ("different mail", other_mail), ("label header", leaking),
                             ("no content digest", unmatched)):
            with self.assertRaises(RuntimeError, msg=name):
                check_saved_analysis(result, MAIL, "saved.json")
        check_saved_analysis(saved_result(), MAIL, "saved.json")

    def test_label_header_in_last_position_is_stripped_for_crlf_and_lf(self):
        for newline in (b"\r\n", b"\n"):
            plain = newline.join([b"Subject: s", b"From: a@b.example"]) + newline * 2 + b"body"
            labelled = newline.join([b"Subject: s", b"From: a@b.example", b"X-Dataset-Label: phishing"]) \
                + newline * 2 + b"body"
            folded = newline.join([b"Subject: s", b"From: a@b.example", b"X-Dataset-Label: phishing",
                                   b"\tcontinued"]) + newline * 2 + b"body"
            for raw in (labelled, folded):
                cleaned, removed = strip_label_headers(raw)
                self.assertEqual(removed, 1)
                self.assertEqual(cleaned, plain)
                self.assertEqual(mail_digest(raw), mail_digest(plain))

    def test_identity_of_header_only_input_ignores_label_headers(self):
        plain = b"Subject: s\r\nFrom: a@b.example\r\n"
        for labelled in (b"Subject: s\r\nX-Dataset-Label: phishing\r\nFrom: a@b.example\r\n",
                         b"Subject: s\r\nFrom: a@b.example\r\nX-Synthetic-Data: true"):
            self.assertEqual(mail_digest(labelled), mail_digest(plain))
        self.assertNotEqual(mail_digest(b"Subject: other\r\n"), mail_digest(plain))

    def test_mail_identity_ignores_only_dataset_label_headers(self):
        labelled = MAIL.replace(b"Subject: s", b"X-Dataset-Label: phishing\r\nX-Synthetic-Data: true\r\nSubject: s")
        self.assertEqual(mail_digest(labelled), mail_digest(MAIL))
        self.assertNotEqual(mail_digest(MAIL.replace(b"body", b"other")), mail_digest(MAIL))
        self.assertEqual(combined_digest(["b", "a"]), combined_digest(["a", "b"]))

    def test_training_evidence_must_match_the_files_on_disk(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / "a.eml").write_bytes(MAIL)
            (base / "b.eml").write_bytes(MAIL.replace(b"body", b"second"))
            training = [{"eml": "a.eml"}, {"eml": "b.eml"}]
            evidence = [{"eml": "a.eml", "eml_sha256": mail_digest(MAIL)},
                        {"eml": "b.eml", "eml_sha256": mail_digest(MAIL.replace(b"body", b"second"))}]
            digest = verify_evidence_binding(training, evidence, [0, 1], base)
            self.assertEqual(digest, combined_digest(row["eml_sha256"] for row in evidence))
            (base / "b.eml").write_bytes(b"Subject: edited\r\n\r\nlater")
            with self.assertRaises(ValueError):
                verify_evidence_binding(training, evidence, [0, 1], base)
            with self.assertRaises(ValueError):
                verify_evidence_binding(training, [{"eml": "a.eml"}], [0], base)
            (base / "b.eml").write_bytes(MAIL)
            duplicated = [evidence[0], {"eml": "b.eml", "eml_sha256": mail_digest(MAIL)}]
            with self.assertRaises(ValueError):
                verify_evidence_binding(training, duplicated, [0, 1], base)

    def test_training_limitation_describes_how_evidence_was_observed(self):
        self.assertIn("offline", training_data_limitation([{}, {"extraction_mode": "offline"}]))
        mixed = training_data_limitation([{"extraction_mode": "offline"}, {"extraction_mode": "saved_live"}])
        self.assertIn("1 offline", mixed)
        self.assertIn("1 saved_live", mixed)


class HoldoutSplitTests(unittest.TestCase):
    def rows(self, groups):
        return [{"eml": f"{g}-{i}-{label}.eml", "label": label, "group_id": g}
                for g in groups for i in range(3) for label in (0, 1)]

    def test_groups_are_never_divided_and_split_is_repeatable(self):
        rows = self.rows([f"group{i}" for i in range(40)])
        train, holdout = split_rows(rows, 0.3, "seed")
        self.assertFalse({r["group_id"] for r in train} & {r["group_id"] for r in holdout})
        self.assertTrue(train and holdout)
        self.assertEqual((train, holdout), split_rows(rows, 0.3, "seed"))
        self.assertTrue(all(r["split"] == "test" for r in holdout))

    def test_adding_new_groups_never_moves_existing_groups(self):
        first = [f"group{i}" for i in range(20)]
        before = {g: in_holdout(g, 0.3, "seed") for g in first}
        _, holdout = split_rows(self.rows(first + [f"new{i}" for i in range(20)]), 0.3, "seed")
        held = {r["group_id"] for r in holdout}
        self.assertEqual({g for g in first if g in held}, {g for g, value in before.items() if value})

    def test_same_mail_under_two_groups_cannot_straddle_the_split(self):
        with tempfile.TemporaryDirectory() as folder:
            def mail(name, body):
                path = Path(folder) / name
                path.write_bytes(body)
                return {"eml": str(path)}
            relabelled = MAIL.replace(b"Subject: s", b"X-Dataset-Split: test\r\nSubject: s")
            check_no_shared_mail([mail("a.eml", MAIL)], [mail("b.eml", MAIL.replace(b"body", b"x"))])
            with self.assertRaises(ValueError):
                check_no_shared_mail([mail("c.eml", MAIL)], [mail("d.eml", relabelled)])

    def test_rows_without_group_or_label_are_rejected(self):
        with self.assertRaises(ValueError):
            split_rows([{"eml": "a.eml", "label": 1, "group_id": ""}], 0.2, "seed")


class PromotionRuleTests(unittest.TestCase):
    def counts(self, fp, fn, unscored=0):
        return {"fp": fp, "fn": fn, "unscored": unscored}

    def test_candidate_must_not_be_worse_on_any_error_type(self):
        self.assertFalse(promotion_decision(self.counts(3, 0), self.counts(2, 5))["promote"])
        self.assertFalse(promotion_decision(self.counts(0, 6), self.counts(2, 5))["promote"])
        self.assertFalse(promotion_decision(self.counts(0, 0, 1), self.counts(2, 5))["promote"])

    def test_equal_performance_is_not_promoted(self):
        self.assertFalse(promotion_decision(self.counts(2, 5), self.counts(2, 5))["promote"])

    def test_strict_improvement_without_regression_is_promoted(self):
        self.assertTrue(promotion_decision(self.counts(2, 4), self.counts(2, 5))["promote"])

    def test_incomparable_installed_model_is_never_auto_promoted(self):
        self.assertFalse(promotion_decision(self.counts(0, 0), None)["promote"])

    def test_unscored_mail_is_counted_separately(self):
        self.assertEqual(count_outcomes([0, 1, 1, 0], [1, 0, None, 0]),
                         {"rows": 4, "tn": 1, "fp": 1, "fn": 1, "tp": 0, "unscored": 1})

    def test_holdout_must_not_share_groups_or_identical_mail_with_training(self):
        with tempfile.TemporaryDirectory() as folder:
            def mail(name, body):
                path = Path(folder) / name
                path.write_bytes(body)
                return str(path)
            def held(name, body, group):
                return {"eml": mail(name, body), "group_id": group, "eml_sha256": mail_digest(body)}
            training = [{"eml": mail("a.eml", b"one"), "group_id": "g1"}]
            self.assertEqual(check_disjoint(training, [held("b.eml", b"two", "g2")]), {mail_digest(b"one")})
            with self.assertRaises(ValueError):
                check_disjoint(training, [held("c.eml", b"three", "g1")])
            with self.assertRaises(ValueError):
                check_disjoint(training, [held("d.eml", b"one", "g3")])
            # Evidence that was not observed from the file being scored is refused.
            stale = held("e.eml", b"four", "g4")
            Path(stale["eml"]).write_bytes(b"edited afterwards")
            with self.assertRaises(ValueError):
                check_disjoint(training, [stale])
            with self.assertRaises(ValueError):
                check_disjoint(training, [{"eml": mail("f.eml", b"five"), "group_id": "g5"}])

    def test_holdout_identity_ignores_order_and_paths(self):
        a = [{"eml": "x/a.eml", "eml_sha256": "11"}, {"eml": "x/b.eml", "eml_sha256": "22"}]
        b = [{"eml": "y/b.eml", "eml_sha256": "22"}, {"eml": "y/a.eml", "eml_sha256": "11"}]
        self.assertEqual(holdout_identity(a), holdout_identity(b))
        self.assertNotEqual(holdout_identity(a), holdout_identity(a[:1]))

    def test_install_switches_config_and_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            models = root / "models"
            models.mkdir()
            config = root / "engine_config.json"
            config.write_text(json.dumps({"semantic_ml_model": "models/old-s.json",
                                          "ml_verdict_model": "models/old-v.json", "razor_timeout": 25}),
                              encoding="utf-8")
            semantic, verdict = root / "s.json", root / "v.json"
            semantic.write_text(json.dumps({"model_id": "sem-new"}), encoding="utf-8")
            verdict.write_text(json.dumps({"model_id": "ver-new", "promoted_to_gui": False}), encoding="utf-8")
            install(semantic, verdict, {"model_id": "ver-new"}, models, config)
            installed = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual(installed["ml_verdict_model"], "models/ver-new.json")
            self.assertEqual(installed["semantic_ml_model"], "models/sem-new.json")
            self.assertEqual(installed["razor_timeout"], 25)
            self.assertTrue(json.loads((models / "ver-new.json").read_text(encoding="utf-8"))["promoted_to_gui"])
            self.assertTrue((models / "ver-new-promotion.json").is_file())
            self.assertFalse(list(models.glob("*.installing")))
            before = config.read_text(encoding="utf-8")
            with self.assertRaises(FileExistsError):
                install(semantic, verdict, {"model_id": "ver-new"}, models, config)
            self.assertEqual(config.read_text(encoding="utf-8"), before)
            self.assertTrue((models / "ver-new.json").is_file())  # the earlier install is untouched
            with self.assertRaises(ValueError):
                check_install_targets_free(install_targets(semantic, verdict, models))

    def test_failed_install_restores_config_and_removes_new_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            models = root / "models"
            models.mkdir()
            config = root / "engine_config.json"
            original = json.dumps({"semantic_ml_model": "models/old-s.json", "ml_verdict_model": "models/old-v.json"})
            config.write_text(original, encoding="utf-8")
            semantic, verdict = root / "s.json", root / "v.json"
            semantic.write_text(json.dumps({"model_id": "sem-new"}), encoding="utf-8")
            verdict.write_text(json.dumps({"model_id": "ver-new"}), encoding="utf-8")
            # The promotion record already exists: the third exclusive create fails
            # after both model files were written.
            (models / "ver-new-promotion.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                install(semantic, verdict, {"model_id": "ver-new"}, models, config)
            self.assertEqual(config.read_text(encoding="utf-8"), original)
            self.assertFalse((models / "sem-new.json").exists())
            self.assertFalse((models / "ver-new.json").exists())
            self.assertEqual((models / "ver-new-promotion.json").read_text(encoding="utf-8"), "{}")
            self.assertFalse(list(root.glob("*.installing")))
            # A failure after the config switch puts the old config back.
            (models / "ver-new-promotion.json").unlink()
            real_loads, real_replace = json.loads, os.replace
            state = {"switched": False}
            def tracking_replace(source, target):
                real_replace(source, target)
                if Path(target) == config and not str(source).endswith(".restore"):
                    state["switched"] = True
            def failing_loads(text, *a, **k):
                if state["switched"]:  # the read-back after the config switch
                    raise OSError("disk error after switch")
                return real_loads(text, *a, **k)
            promote_module.json.loads, promote_module.os.replace = failing_loads, tracking_replace
            try:
                with self.assertRaises(OSError):
                    install(semantic, verdict, {"model_id": "ver-new"}, models, config)
            finally:
                promote_module.json.loads, promote_module.os.replace = real_loads, real_replace
            self.assertTrue(state["switched"])  # the failure really happened after the switch
            self.assertEqual(config.read_text(encoding="utf-8"), original)
            self.assertFalse(list(models.iterdir()))
            self.assertFalse(list(root.glob("engine_config.json.*")))

    def test_semantic_artifact_is_installed_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            models = root / "models"
            models.mkdir()
            config = root / "engine_config.json"
            config.write_text(json.dumps({"semantic_ml_model": "a", "ml_verdict_model": "b"}), encoding="utf-8")
            semantic, verdict = root / "s.json", root / "v.json"
            semantic.write_bytes(b'{"model_id":   "sem-new",\n "coef": [0.1]}\n')  # unusual formatting on purpose
            verdict.write_text(json.dumps({"model_id": "ver-new"}), encoding="utf-8")
            install(semantic, verdict, {"model_id": "ver-new"}, models, config)
            self.assertEqual((models / "sem-new.json").read_bytes(), semantic.read_bytes())

    def test_schema_mismatch_is_a_distinct_error(self):
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / "model.json"
            artifact.write_text(json.dumps({"model_id": "m", "feature_schema": "ml-verdict-features-v0",
                                            "feature_names": list(FEATURE_NAMES), "coef": [0.0] * len(FEATURE_NAMES),
                                            "intercept": 0.0}), encoding="utf-8")
            with self.assertRaises(SchemaMismatchError):
                analyze_ml_verdict(live_result(), artifact)
            self.assertTrue(issubclass(SchemaMismatchError, ValueError))  # the GUI still reports 'unavailable'

    def test_training_text_is_the_text_the_gui_embeds(self):
        korean = EmailMessage()
        korean["Subject"] = "계정 확인 안내"
        korean.set_content("안녕하세요. 계정 정보를 확인해 주시기 바랍니다. 감사합니다.")
        self.assertIn("계정", serving_text(korean, None))
        foreign = EmailMessage()
        foreign["Subject"] = "Account verification required"
        foreign.set_content("Dear customer, please verify your account information today. Thank you very much.")
        # Without a translation model the GUI cannot score this mail, so it is not a training row.
        with self.assertRaises(ValueError):
            serving_text(foreign, None)


class LabelToolTests(unittest.TestCase):
    def test_row_records_saved_analysis_and_observation_labels(self):
        with tempfile.TemporaryDirectory() as folder:
            eml = Path(folder) / "mail.eml"
            eml.write_bytes(MAIL)
            saved = Path(folder) / "final_analysis_result.json"
            saved.write_text(json.dumps(saved_result()), encoding="utf-8")
            labels = parse_observation_labels(["attachment_antivirus_report=false_positive"])
            row = build_row(eml, 0, "bank-notice", saved, labels)
            self.assertEqual(row["analysis_result"], str(saved.resolve()))
            self.assertEqual(row["observation_labels"], {"attachment_antivirus_report": "false_positive"})
            manifest = Path(folder) / "labelled" / "real_manifest.jsonl"
            append_row(manifest, row)
            with self.assertRaises(ValueError):
                append_row(manifest, row)
            self.assertEqual(len(manifest.read_text(encoding="utf-8").splitlines()), 1)

    def test_invalid_inputs_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_observation_labels(["razor_catalogue_match=maybe"])
        with tempfile.TemporaryDirectory() as folder:
            eml = Path(folder) / "mail.eml"
            eml.write_bytes(b"x")
            with self.assertRaises(ValueError):
                build_row(eml, 1, "  ", None, {})
            error = Path(folder) / "error.json"
            error.write_text(json.dumps({"verdict": "error"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                build_row(eml, 1, "g", error, {})


if __name__ == "__main__":
    unittest.main()
