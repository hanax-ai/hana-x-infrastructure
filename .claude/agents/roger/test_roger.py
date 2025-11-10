#!/usr/bin/env python3
"""
Roger Orchestrator - Unit Tests.

Comprehensive test suite for Roger Phase 2 implementation.

This module contains unit tests for all Roger components including finding
deduplication, normalization, defect logging, and the Layer 3 stub. Tests
ensure correct functionality of Roger's core features.

Test Coverage:
- Layer 3 stub functionality (disabled state, empty results)
- Finding utilities (deduplication, normalization, summaries)
- Defect logger (create, append, deduplicate fingerprints)
- Category normalization and fingerprint generation
- Roger ID assignment and finding format conversion

Test Classes:
    - TestLayer3Stub: Tests for Layer 3 CodeRabbit stub
    - TestFindingUtils: Tests for finding utilities
    - TestDefectLogger: Tests for defect logger

Usage:
    python test_roger.py
    pytest test_roger.py -v

Author: Eric Johnson (Senior Developer)
Date: 2025-11-10
Version: 1.0
"""

import sys
import tempfile
import unittest
from pathlib import Path

# Import Roger components
from layer3_stub import CodeRabbitLayer3
from defect_logger import DefectLogger
from finding_utils import (
    normalize_category,
    generate_fingerprint,
    deduplicate_findings,
    normalize_finding,
    normalize_findings,
    generate_summary,
)


class TestLayer3Stub(unittest.TestCase):
    """Test Layer 3 stub implementation"""

    def test_stub_disabled_by_default(self):
        """Layer 3 should be disabled by default"""
        layer3 = CodeRabbitLayer3()
        self.assertFalse(layer3.is_enabled())

    def test_stub_returns_empty_findings(self):
        """Stub should return empty findings list"""
        layer3 = CodeRabbitLayer3()
        findings = layer3.analyze_files(["/srv/cc/test.py"])
        self.assertEqual(findings, [])

    def test_cache_stats_empty(self):
        """Cache stats should return empty values"""
        layer3 = CodeRabbitLayer3()
        stats = layer3.get_cache_stats()
        self.assertEqual(stats["cache_enabled"], False)
        self.assertEqual(stats["cache_hits"], 0)
        self.assertEqual(stats["total_entries"], 0)

    def test_clear_cache_returns_zero(self):
        """Clear cache should return 0"""
        layer3 = CodeRabbitLayer3()
        cleared = layer3.clear_cache()
        self.assertEqual(cleared, 0)


class TestFindingUtils(unittest.TestCase):
    """Test finding utilities"""

    def test_normalize_category(self):
        """Test category normalization"""
        self.assertEqual(normalize_category("vulnerability"), "security")
        self.assertEqual(normalize_category("code_smell"), "quality")
        self.assertEqual(normalize_category("type_issue"), "type_error")
        self.assertEqual(normalize_category("cognitive_load"), "complexity")
        self.assertEqual(normalize_category("style"), "formatting")
        self.assertEqual(normalize_category("security"), "security")  # No change

    def test_generate_fingerprint(self):
        """Test fingerprint generation"""
        fp1 = generate_fingerprint("/srv/cc/test.py", 42, "security")
        fp2 = generate_fingerprint("/srv/cc/test.py", 42, "security")
        fp3 = generate_fingerprint("/srv/cc/test.py", 43, "security")

        # Same inputs should produce same fingerprint
        self.assertEqual(fp1, fp2)

        # Different inputs should produce different fingerprints
        self.assertNotEqual(fp1, fp3)

        # Fingerprint should be 16 hex characters
        self.assertEqual(len(fp1), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in fp1))

    def test_deduplicate_layer1_precedence(self):
        """Test Layer 1 precedence in deduplication"""
        layer1 = [
            {
                "file": "/srv/cc/test.py",
                "line": 42,
                "category": "security",
                "message": "SQL injection (Layer 1)",
                "priority": "P1",
                "source": "bandit",
            }
        ]

        layer3 = [
            {
                "file": "/srv/cc/test.py",
                "line": 42,
                "category": "security",
                "message": "SQL injection (Layer 3)",
                "priority": "P1",
                "source": "coderabbit",
            }
        ]

        deduplicated = deduplicate_findings(layer1, layer3)

        # Should only have 1 finding (Layer 1 takes precedence)
        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(deduplicated[0]["message"], "SQL injection (Layer 1)")

    def test_deduplicate_complementary_findings(self):
        """Test complementary findings (same location, different categories)"""
        layer1 = [
            {
                "file": "/srv/cc/test.py",
                "line": 42,
                "category": "security",
                "message": "Security issue",
                "priority": "P1",
                "source": "bandit",
            }
        ]

        layer3 = [
            {
                "file": "/srv/cc/test.py",
                "line": 42,
                "category": "solid_violation",
                "message": "SOLID violation",
                "priority": "P2",
                "source": "coderabbit",
            }
        ]

        deduplicated = deduplicate_findings(layer1, layer3)

        # Should have 2 findings (complementary - different categories)
        self.assertEqual(len(deduplicated), 2)

    def test_deduplicate_unique_layer3_categories(self):
        """Test unique Layer 3 categories are never deduplicated"""
        layer1 = []

        layer3 = [
            {
                "file": "/srv/cc/test.py",
                "line": 42,
                "category": "solid_violation",
                "message": "SOLID violation",
                "priority": "P2",
                "source": "coderabbit",
            },
            {
                "file": "/srv/cc/test.py",
                "line": 42,
                "category": "design_pattern",
                "message": "Design pattern issue",
                "priority": "P2",
                "source": "coderabbit",
            },
        ]

        deduplicated = deduplicate_findings(layer1, layer3)

        # Should have 2 findings (unique Layer 3 categories)
        self.assertEqual(len(deduplicated), 2)

    def test_normalize_finding(self):
        """Test finding normalization"""
        finding = {
            "priority": "P1",
            "category": "vulnerability",  # Should be normalized to 'security'
            "source": "bandit",
            "file": "/srv/cc/test.py",
            "line": 42,
            "message": "SQL injection",
            "details": "User input not sanitized",
            "fix": "Use parameterized queries",
        }

        normalized = normalize_finding(finding, "ROG-0001")

        self.assertEqual(normalized["id"], "ROG-0001")
        self.assertEqual(normalized["priority"], "P1")
        self.assertEqual(normalized["category"], "security")  # Normalized
        self.assertEqual(normalized["source_layer"], "layer1")  # Inferred
        self.assertEqual(normalized["source_tool"], "bandit")
        self.assertEqual(normalized["file"], "/srv/cc/test.py")
        self.assertEqual(normalized["line"], 42)
        self.assertEqual(normalized["message"], "SQL injection")
        self.assertIsNotNone(normalized["fingerprint"])

    def test_normalize_findings_batch(self):
        """Test batch normalization with ID assignment"""
        findings = [
            {
                "message": "Issue 1",
                "file": "test1.py",
                "category": "security",
                "source": "bandit",
            },
            {
                "message": "Issue 2",
                "file": "test2.py",
                "category": "quality",
                "source": "pylint",
            },
            {
                "message": "Issue 3",
                "file": "test3.py",
                "category": "types",
                "source": "mypy",
            },
        ]

        normalized = normalize_findings(findings)

        self.assertEqual(len(normalized), 3)
        self.assertEqual(normalized[0]["id"], "ROG-0001")
        self.assertEqual(normalized[1]["id"], "ROG-0002")
        self.assertEqual(normalized[2]["id"], "ROG-0003")

    def test_generate_summary(self):
        """Test summary generation"""
        findings = [
            {"priority": "P0", "category": "security", "source_layer": "layer1"},
            {"priority": "P1", "category": "quality", "source_layer": "layer1"},
            {"priority": "P1", "category": "quality", "source_layer": "layer1"},
            {"priority": "P2", "category": "complexity", "source_layer": "layer3"},
        ]

        summary = generate_summary(findings)

        self.assertEqual(summary["total_issues"], 4)
        self.assertEqual(summary["by_priority"]["P0"], 1)
        self.assertEqual(summary["by_priority"]["P1"], 2)
        self.assertEqual(summary["by_priority"]["P2"], 1)
        self.assertEqual(summary["by_category"]["security"], 1)
        self.assertEqual(summary["by_category"]["quality"], 2)
        self.assertEqual(summary["by_layer"]["layer1"], 3)
        self.assertEqual(summary["by_layer"]["layer3"], 1)
        self.assertIn("Found 4 issues", summary["summary_text"])


class TestDefectLogger(unittest.TestCase):
    """Test defect logger"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_path = Path(self.temp_dir) / "test-defects.md"

    def tearDown(self):
        """Clean up test fixtures"""
        if self.log_path.exists():
            self.log_path.unlink()

    def test_create_defect_log(self):
        """Test creating new defect log"""
        findings = [
            {
                "id": "ROG-0001",
                "priority": "P1",
                "category": "security",
                "source_layer": "layer1",
                "source_tool": "bandit",
                "file": "/srv/cc/test.py",
                "line": 42,
                "message": "SQL injection",
                "details": "User input not sanitized",
                "fix": "Use parameterized queries",
                "fingerprint": "a1b2c3d4e5f6a7b8",
            }
        ]

        logger = DefectLogger(str(self.log_path))
        count = logger.create_defect_log(findings, "Test Project")

        self.assertEqual(count, 1)
        self.assertTrue(self.log_path.exists())

        # Verify log content
        content = self.log_path.read_text()
        self.assertIn("# Defect Log - Test Project", content)
        self.assertIn("### DEF-0001:", content)
        self.assertIn("SQL injection", content)
        self.assertIn("[P1]", content)
        self.assertIn("bandit", content)

    def test_append_defects(self):
        """Test appending defects to existing log"""
        # Create initial log
        findings1 = [
            {
                "id": "ROG-0001",
                "priority": "P1",
                "category": "security",
                "source_layer": "layer1",
                "source_tool": "bandit",
                "file": "/srv/cc/test.py",
                "line": 42,
                "message": "Issue 1",
                "details": "Details 1",
                "fix": "Fix 1",
                "fingerprint": "a1b2c3d4e5f6a7b8",
            }
        ]

        logger = DefectLogger(str(self.log_path))
        logger.create_defect_log(findings1, "Test Project")

        # Append new findings
        findings2 = [
            {
                "id": "ROG-0002",
                "priority": "P2",
                "category": "quality",
                "source_layer": "layer1",
                "source_tool": "pylint",
                "file": "/srv/cc/test.py",
                "line": 100,
                "message": "Issue 2",
                "details": "Details 2",
                "fix": "Fix 2",
                "fingerprint": "b2c3d4e5f6a7b8c9",
            }
        ]

        count = logger.append_defects(findings2)

        self.assertEqual(count, 1)

        # Verify both defects in log
        content = self.log_path.read_text()
        self.assertIn("DEF-0001", content)
        self.assertIn("DEF-0002", content)
        self.assertIn("Issue 1", content)
        self.assertIn("Issue 2", content)

    def test_deduplication_on_append(self):
        """Test that duplicate fingerprints are skipped on append"""
        findings1 = [
            {
                "id": "ROG-0001",
                "priority": "P1",
                "category": "security",
                "source_layer": "layer1",
                "source_tool": "bandit",
                "file": "/srv/cc/test.py",
                "line": 42,
                "message": "Issue 1",
                "details": "Details 1",
                "fix": "Fix 1",
                "fingerprint": "a1b2c3d4e5f6a7b8",
            }
        ]

        logger = DefectLogger(str(self.log_path))
        logger.create_defect_log(findings1, "Test Project")

        # Try to append same fingerprint
        findings2 = [
            {
                "id": "ROG-0002",
                "priority": "P1",
                "category": "security",
                "source_layer": "layer1",
                "source_tool": "bandit",
                "file": "/srv/cc/test.py",
                "line": 42,
                "message": "Issue 1 (duplicate)",
                "details": "Details 1",
                "fix": "Fix 1",
                "fingerprint": "a1b2c3d4e5f6a7b8",  # Same fingerprint
            }
        ]

        count = logger.append_defects(findings2)

        self.assertEqual(count, 0)  # Duplicate skipped

    def test_get_defect_summary(self):
        """Test getting defect summary"""
        findings = [
            {
                "id": "ROG-0001",
                "priority": "P0",
                "category": "security",
                "source_layer": "layer1",
                "source_tool": "bandit",
                "file": "test.py",
                "line": 1,
                "message": "Critical",
                "details": "",
                "fix": "",
                "fingerprint": "a1",
            },
            {
                "id": "ROG-0002",
                "priority": "P1",
                "category": "quality",
                "source_layer": "layer1",
                "source_tool": "pylint",
                "file": "test.py",
                "line": 2,
                "message": "High",
                "details": "",
                "fix": "",
                "fingerprint": "b2",
            },
            {
                "id": "ROG-0003",
                "priority": "P2",
                "category": "types",
                "source_layer": "layer1",
                "source_tool": "mypy",
                "file": "test.py",
                "line": 3,
                "message": "Medium",
                "details": "",
                "fix": "",
                "fingerprint": "c3",
            },
        ]

        logger = DefectLogger(str(self.log_path))
        logger.create_defect_log(findings, "Test Project")

        summary = logger.get_defect_summary()

        self.assertEqual(summary["P0"], 1)
        self.assertEqual(summary["P1"], 1)
        self.assertEqual(summary["P2"], 1)
        self.assertEqual(summary["P3"], 0)
        self.assertEqual(summary["P4"], 0)

    def test_clear_log(self):
        """Test clearing log file"""
        findings = [
            {
                "id": "ROG-0001",
                "priority": "P1",
                "category": "security",
                "source_layer": "layer1",
                "source_tool": "bandit",
                "file": "test.py",
                "line": 1,
                "message": "Issue",
                "details": "",
                "fix": "",
                "fingerprint": "a1",
            }
        ]

        logger = DefectLogger(str(self.log_path))
        logger.create_defect_log(findings, "Test Project")

        self.assertTrue(self.log_path.exists())

        cleared = logger.clear_log()

        self.assertTrue(cleared)
        self.assertFalse(self.log_path.exists())


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestLayer3Stub))
    suite.addTests(loader.loadTestsFromTestCase(TestFindingUtils))
    suite.addTests(loader.loadTestsFromTestCase(TestDefectLogger))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    SYS_EXIT_CODE = run_tests()
    sys.exit(SYS_EXIT_CODE)
