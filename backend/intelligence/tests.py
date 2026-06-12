"""
Phase 11 — tests for the AI anomaly detection module.

Extractor tests are pure/fast (SimpleTestCase). The train→detect test exercises
the real scikit-learn pipeline against the bundled datasets in a temp model dir.
"""
import tempfile
from pathlib import Path

from django.test import SimpleTestCase, TestCase, override_settings

from intelligence.ml.feature_extractor import (
    SQLiFeatureExtractor, XSSFeatureExtractor, BruteForceFeatureExtractor,
)
from intelligence.ml.detector import CerberusDetector


class FeatureExtractorTests(SimpleTestCase):
    def test_sqli_flags_classic_payload(self):
        f = SQLiFeatureExtractor().extract("' OR 1=1--")
        self.assertTrue(f["has_comment"])
        self.assertGreater(f["special_char_ratio"], 0.1)
        self.assertGreater(f["quote_count"], 0)

    def test_sqli_union_and_sleep(self):
        f = SQLiFeatureExtractor().extract("1 UNION SELECT sleep(5)--")
        self.assertTrue(f["has_union"])
        self.assertTrue(f["has_sleep"])

    def test_xss_flags_script_tag(self):
        f = XSSFeatureExtractor().extract("<script>alert(1)</script>")
        self.assertTrue(f["has_script_tag"])
        self.assertGreaterEqual(f["tag_count"], 1)

    def test_xss_event_handler(self):
        f = XSSFeatureExtractor().extract("<img src=x onerror=alert(1)>")
        self.assertTrue(f["has_event_handler"])

    def test_bruteforce_zero_vector_on_no_events(self):
        f = BruteForceFeatureExtractor().extract("1.2.3.4", [], {})
        self.assertEqual(f["request_count"], 0)


class DetectorFallbackTests(SimpleTestCase):
    """With no trained model present, detectors must fail safe (no crash)."""

    def setUp(self):
        # Point at an empty model dir so nothing loads.
        self._tmp = tempfile.TemporaryDirectory()
        self._override = override_settings(
            INTELLIGENCE_MODELS=Path(self._tmp.name) / "models")
        self._override.enable()
        # Reset class cache.
        CerberusDetector._models = {}
        CerberusDetector._vectorizers = {}

    def tearDown(self):
        self._override.disable()
        self._tmp.cleanup()

    def test_sqli_fallback_when_unloaded(self):
        r = CerberusDetector().detect_sqli("' OR 1=1--")
        self.assertFalse(r["detected"])
        self.assertTrue(r.get("fallback"))

    def test_bruteforce_static_rule_fallback(self):
        # >10 failed attempts triggers the baseline-phase static rule.
        events = [{"success": False, "username": "a", "endpoint": "/l", "timestamp": None}
                  for _ in range(12)]
        r = CerberusDetector().detect_bruteforce("9.9.9.9", events)
        self.assertTrue(r["detected"])
        self.assertTrue(r.get("fallback"))


class TrainAndDetectTests(TestCase):
    """End-to-end: train v1 from bundled data, then assert canonical detections."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls._override = override_settings(
            INTELLIGENCE_MODELS=root / "models",
            INTELLIGENCE_TRAINING_DATA=root / "training_data",
        )
        cls._override.enable()
        from intelligence.ml import trainer
        trainer.train_sqli_model()
        trainer.train_xss_model()
        CerberusDetector._models = {}
        CerberusDetector._vectorizers = {}
        CerberusDetector.load_all_models()

    @classmethod
    def tearDownClass(cls):
        cls._override.disable()
        cls._tmp.cleanup()
        super().tearDownClass()

    def test_sqli_detection_high_confidence(self):
        r = CerberusDetector().detect_sqli("' OR 1=1--")
        self.assertTrue(r["detected"])
        self.assertGreater(r["confidence"], 0.85)

    def test_xss_detection_high_confidence(self):
        r = CerberusDetector().detect_xss("<script>alert(1)</script>")
        self.assertTrue(r["detected"])
        self.assertGreater(r["confidence"], 0.80)

    def test_benign_not_flagged(self):
        self.assertFalse(CerberusDetector().detect_sqli("q=O'Brien")["detected"])
        self.assertFalse(CerberusDetector().detect_xss("search=best laptop bag")["detected"])
