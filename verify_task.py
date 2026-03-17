import sys
import os
import logging
from unittest import TestCase, main
from src.core.recon_pipeline import ReconPipeline, AllowedBugClasses
from src.ai.report_generator import ReportGenerator
from src.core.background_worker import BackgroundWorker

logging.basicConfig(level=logging.ERROR)

class TestPhase20(TestCase):
    def test_recon_payloads_expanded(self):
        """Regression Audit: Ensure new SSTI and SSRF payload bug classes exist"""
        self.assertIn("ssti", [c.value for c in AllowedBugClasses])
        self.assertIn("ssrf", [c.value for c in AllowedBugClasses])
        
    def test_report_generator_works(self):
        """Test if the local ReportGenerator generates a ReportContent correctly"""
        rg = ReportGenerator()
        finding = {
            "target": "example.com",
            "bug_class": "ssti",
            "severity": "Critical",
            "evidence": "Template expression evaluated",
            "poc_log": "GET / HTTP/1.1\n\n{{7*7}}"
        }
        report = rg.generate_report(finding)
        self.assertIsNotNone(report)
        self.assertEqual(report.title, "Server-Side Template Injection (SSTI) in example.com")
        self.assertEqual(report.severity, "Critical")
        
    def test_background_worker_import(self):
        """Regression Audit: Ensure background_worker logic doesn't crash on init"""
        worker = BackgroundWorker()
        self.assertIsNotNone(worker)
        self.assertFalse(worker.practice_mode) # By default it is false locally without ENV

if __name__ == "__main__":
    sys.exit(main(verbosity=2))
