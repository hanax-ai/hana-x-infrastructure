#!/usr/bin/env python3
"""
Roger Linter Aggregator - Production Implementation

Aggregates results from multiple proven linters with advanced features:
- Parallel execution for performance (ThreadPoolExecutor)
- Issue deduplication (fingerprint-based)
- Security hardening (path validation)
- Graceful error handling
- 6 Integrated Linters:
  * bandit (security scanning)
  * pylint (code quality)
  * mypy (type checking)
  * radon (complexity metrics)
  * black (formatting)
  * pytest (test coverage)

Author: Eric Johnson (Senior Developer)
Date: 2025-11-10
Version: 1.0
Layer: POC4 CodeRabbit Layer 1 (Foundation)
"""

import json
import subprocess  # nosec B404 - Required for executing linters securely with validated paths
import sys
import re
import hashlib
import tempfile
from pathlib import Path
import time
import argparse
import traceback
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

# Linter paths (absolute paths for security)
LINTER_PATHS = {
    "bandit": "/home/agent0/.local/bin/bandit",
    "pylint": "/home/agent0/.local/bin/pylint",
    "mypy": "/home/agent0/.local/bin/mypy",
    "radon": "/home/agent0/.local/bin/radon",
    "black": "/home/agent0/.local/bin/black",
    "pytest": "/home/agent0/.local/bin/pytest",
}


class Priority(str, Enum):
    """Issue priority levels"""

    CRITICAL = "P0"  # Critical - must fix
    HIGH = "P1"  # High - fix soon
    MEDIUM = "P2"  # Medium - fix when convenient
    LOW = "P3"  # Low - nice to fix
    INFO = "P4"  # Info - informational


class Category(str, Enum):
    """Issue categories"""

    SECURITY = "security"
    QUALITY = "quality"
    TYPES = "types"
    COMPLEXITY = "complexity"
    FORMATTING = "formatting"
    TESTING = "testing"


@dataclass
class Issue:  # pylint: disable=too-many-instance-attributes
    """Normalized issue from any linter"""

    id: str
    priority: Priority
    category: Category
    source: str  # Which linter found it
    file: str
    line: Optional[int]
    message: str
    details: str
    fix: Optional[str] = None
    fingerprint: Optional[str] = None  # For deduplication

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class AggregatedResult:  # pylint: disable=too-many-instance-attributes
    """Combined results from all linters"""

    status: str
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    info_issues: int
    issues_by_category: Dict[str, int]
    issues: List[Issue]
    linters_run: List[str]
    linters_failed: List[str]
    execution_time_seconds: float
    summary: str

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "status": self.status,
            "total_issues": self.total_issues,
            "critical_issues": self.critical_issues,
            "high_issues": self.high_issues,
            "medium_issues": self.medium_issues,
            "low_issues": self.low_issues,
            "info_issues": self.info_issues,
            "issues_by_category": self.issues_by_category,
            "issues": [issue.to_dict() for issue in self.issues],
            "linters_run": self.linters_run,
            "linters_failed": self.linters_failed,
            "execution_time_seconds": self.execution_time_seconds,
            "summary": self.summary,
        }


class SecurityError(Exception):
    """Raised when path validation fails"""


class LinterAggregator:  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    """Aggregates results from multiple linters with parallel execution"""

    def __init__(self, path: str = ".", verbose: bool = False, parallel: bool = True):
        """
        Initialize aggregator

        Args:
            path: Path to analyze
            verbose: Enable verbose output
            parallel: Enable parallel execution (default: True)
        """
        self.path = self._validate_path(path)
        self.verbose = verbose
        self.parallel = parallel
        self.issues: List[Issue] = []
        self.issue_counter = 0
        self.linters_run: List[str] = []
        self.linters_failed: List[str] = []
        self.seen_fingerprints: Set[str] = set()

        # Validate linters are accessible
        self._validate_linters()

    def _validate_path(self, path: str) -> Path:
        """
        Validate and sanitize path

        Security: Prevent directory traversal attacks
        """
        try:
            # Resolve to absolute path
            resolved = Path(path).resolve()

            # Check path exists
            if not resolved.exists():
                raise SecurityError(f"Path does not exist: {path}")

            # Check it's within allowed directories
            allowed_prefixes = [
                Path("/srv/cc/"),
                Path("/home/agent0/"),
                Path(tempfile.gettempdir()),
            ]

            if not any(
                str(resolved).startswith(str(prefix)) for prefix in allowed_prefixes
            ):
                raise SecurityError(f"Path outside allowed directories: {path}")

            return resolved

        except Exception as e:
            raise SecurityError(f"Invalid path: {path} - {e}") from e

    def _validate_linters(self):
        """Validate all linters are accessible"""
        missing = []
        for name, path in LINTER_PATHS.items():
            if not Path(path).exists():
                missing.append(f"{name} ({path})")

        if missing:
            raise RuntimeError(
                f"Missing linters: {', '.join(missing)}\n"
                "Install with: pip install --break-system-packages "
                "bandit pylint mypy radon black pytest pytest-cov"
            )

    def _generate_fingerprint(self, file: str, line: Optional[int], rule: str) -> str:
        """
        Generate fingerprint for issue deduplication

        Fingerprint = hash(file + line + rule)
        """
        key = f"{file}:{line or 0}:{rule}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _add_issue(self, issue: Issue) -> bool:
        """
        Add issue with deduplication

        Returns:
            True if added, False if duplicate
        """
        # Generate fingerprint
        fingerprint = self._generate_fingerprint(
            issue.file, issue.line, f"{issue.source}:{issue.message[:50]}"
        )
        issue.fingerprint = fingerprint

        # Check for duplicate
        if fingerprint in self.seen_fingerprints:
            if self.verbose:
                print(f"    → Duplicate issue skipped: {issue.file}:{issue.line}")
            return False

        # Add issue
        self.seen_fingerprints.add(fingerprint)
        self.issues.append(issue)
        return True

    def run_all(self) -> AggregatedResult:
        """
        Run all linters and aggregate results

        Uses parallel execution if enabled, otherwise sequential.
        """
        start_time = time.time()

        # Send output to stderr if we're in a non-verbose subprocess mode
        # (this will be captured properly by the orchestrator)
        print("🔍 Running linter suite...", file=sys.stderr)
        if self.parallel:
            print(
                "  ⚡ Parallel execution enabled (ThreadPoolExecutor)", file=sys.stderr
            )

        if self.parallel:
            self._run_parallel()
        else:
            self._run_sequential()

        execution_time = time.time() - start_time

        # Aggregate results
        return self._aggregate(execution_time)

    def _run_parallel(self):
        """Run all linters in parallel"""
        linter_functions = [
            ("bandit", self._run_bandit),
            ("pylint", self._run_pylint),
            ("mypy", self._run_mypy),
            ("radon", self._run_radon),
            ("black", self._run_black),
            ("pytest", self._run_pytest),
        ]

        with ThreadPoolExecutor(max_workers=6) as executor:
            # Submit all linters
            futures = {executor.submit(func): name for name, func in linter_functions}

            # Collect results as they complete
            for future in as_completed(futures):
                linter_name = futures[future]
                try:
                    future.result()
                except (subprocess.TimeoutExpired, RuntimeError, OSError) as e:
                    if self.verbose:
                        print(f"  ✗ {linter_name} exception: {e}")

    def _run_sequential(self):
        """Run all linters sequentially"""
        self._run_bandit()
        self._run_pylint()
        self._run_mypy()
        self._run_radon()
        self._run_black()
        self._run_pytest()

    def _run_bandit(self):
        """Run bandit security scanner"""
        print("  → Running bandit (security)...", file=sys.stderr)
        try:
            result = subprocess.run(  # nosec B603
                [LINTER_PATHS["bandit"], "-r", str(self.path), "-f", "json"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                except json.JSONDecodeError as e:
                    if self.verbose:
                        print(f"    ✗ bandit JSON parse error: {e}")
                    self.linters_failed.append("bandit")
                    return

                for item in data.get("results", []):
                    self.issue_counter += 1

                    # Map severity to priority
                    severity_map = {
                        "HIGH": Priority.CRITICAL,
                        "MEDIUM": Priority.HIGH,
                        "LOW": Priority.MEDIUM,
                    }

                    issue = Issue(
                        id=f"BAN-{self.issue_counter:04d}",
                        priority=severity_map.get(
                            item.get("issue_severity", "LOW"), Priority.MEDIUM
                        ),
                        category=Category.SECURITY,
                        source="bandit",
                        file=item["filename"],
                        line=item.get("line_number"),
                        message=item["issue_text"],
                        details=item.get("more_info", ""),
                        fix=self._suggest_security_fix(item.get("test_id", "")),
                    )
                    self._add_issue(issue)

            self.linters_run.append("bandit")
            issue_count = len([i for i in self.issues if i.source == "bandit"])
            print(f"    ✓ bandit: {issue_count} issues found", file=sys.stderr)

        except subprocess.TimeoutExpired:
            print("    ✗ bandit timed out", file=sys.stderr)
            self.linters_failed.append("bandit")
        except (RuntimeError, OSError, json.JSONDecodeError) as e:
            if self.verbose:
                print(f"    ✗ bandit failed: {e}", file=sys.stderr)
            self.linters_failed.append("bandit")

    def _run_pylint(self):
        """Run pylint code quality checker"""
        print("  → Running pylint (quality)...", file=sys.stderr)
        try:
            result = subprocess.run(  # nosec B603
                [
                    LINTER_PATHS["pylint"],
                    str(self.path),
                    "--output-format=json",
                    "--exit-zero",
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                except json.JSONDecodeError as e:
                    if self.verbose:
                        print(f"    ✗ pylint JSON parse error: {e}")
                    self.linters_failed.append("pylint")
                    return

                for item in data:
                    self.issue_counter += 1

                    # Map type to priority
                    type_map = {
                        "error": Priority.CRITICAL,
                        "warning": Priority.HIGH,
                        "convention": Priority.MEDIUM,
                        "refactor": Priority.MEDIUM,
                        "info": Priority.INFO,
                    }

                    issue = Issue(
                        id=f"PYL-{self.issue_counter:04d}",
                        priority=type_map.get(item.get("type", "info"), Priority.INFO),
                        category=Category.QUALITY,
                        source="pylint",
                        file=item.get("path", "unknown"),
                        line=item.get("line"),
                        message=item.get("message", "Unknown issue"),
                        details=(
                            f"{item.get('symbol', 'unknown')} "
                            f"({item.get('message-id', 'unknown')})"
                        ),
                        fix=None,  # Pylint doesn't suggest fixes
                    )
                    self._add_issue(issue)

            self.linters_run.append("pylint")
            issue_count = len([i for i in self.issues if i.source == "pylint"])
            print(f"    ✓ pylint: {issue_count} issues found", file=sys.stderr)

        except subprocess.TimeoutExpired:
            print("    ✗ pylint timed out", file=sys.stderr)
            self.linters_failed.append("pylint")
        except (RuntimeError, OSError, json.JSONDecodeError) as e:
            if self.verbose:
                print(f"    ✗ pylint failed: {e}", file=sys.stderr)
            self.linters_failed.append("pylint")

    def _run_mypy(self):
        """Run mypy type checker (regex-based parsing)"""
        print("  → Running mypy (types)...", file=sys.stderr)
        try:
            result = subprocess.run(  # nosec B603
                [LINTER_PATHS["mypy"], str(self.path)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            # Mypy doesn't output JSON, parse line-by-line with regex
            # Format: filename:line: error: message
            pattern = re.compile(r"^(.+?):(\d+):\s*(error|warning|note):\s*(.+)$")

            for line in result.stdout.split("\n"):
                match = pattern.match(line.strip())
                if match:
                    filename, line_num, severity, message = match.groups()
                    self.issue_counter += 1

                    # Map severity to priority
                    severity_map = {
                        "error": Priority.HIGH,
                        "warning": Priority.MEDIUM,
                        "note": Priority.INFO,
                    }

                    issue = Issue(
                        id=f"MYP-{self.issue_counter:04d}",
                        priority=severity_map.get(severity, Priority.MEDIUM),
                        category=Category.TYPES,
                        source="mypy",
                        file=filename,
                        line=int(line_num),
                        message=message,
                        details="Type checking error",
                        fix="Add or correct type hints",
                    )
                    self._add_issue(issue)

            self.linters_run.append("mypy")
            issue_count = len([i for i in self.issues if i.source == "mypy"])
            print(f"    ✓ mypy: {issue_count} issues found", file=sys.stderr)

        except subprocess.TimeoutExpired:
            print("    ✗ mypy timed out", file=sys.stderr)
            self.linters_failed.append("mypy")
        except (RuntimeError, OSError) as e:
            if self.verbose:
                print(f"    ✗ mypy failed: {e}", file=sys.stderr)
            self.linters_failed.append("mypy")

    def _parse_radon_output(self, stdout: str) -> Optional[Dict]:
        """Parse radon JSON output"""
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as e:
            if self.verbose:
                print(f"    ✗ radon JSON parse error: {e}", file=sys.stderr)
            self.linters_failed.append("radon")
            return None

    def _run_radon(self):
        """Run radon complexity analyzer"""
        print("  → Running radon (complexity)...", file=sys.stderr)
        try:
            result = subprocess.run(  # nosec B603
                [LINTER_PATHS["radon"], "cc", str(self.path), "-j"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.stdout:
                data = self._parse_radon_output(result.stdout)
                if data is None:
                    return

                for file_path, functions in data.items():
                    if isinstance(functions, list):
                        for func_data in functions:
                            self._process_radon_function(file_path, func_data)

            self.linters_run.append("radon")
            issue_count = len([i for i in self.issues if i.source == "radon"])
            print(f"    ✓ radon: {issue_count} issues found", file=sys.stderr)

        except subprocess.TimeoutExpired:
            print("    ✗ radon timed out", file=sys.stderr)
            self.linters_failed.append("radon")
        except (RuntimeError, OSError) as e:
            if self.verbose:
                print(f"    ✗ radon failed: {e}", file=sys.stderr)
            self.linters_failed.append("radon")

    def _process_radon_function(self, file_path: str, func_data: Dict) -> None:
        """Process a single radon function complexity result"""
        complexity = func_data.get("complexity", 0)
        if complexity > 10:  # Threshold: 10
            self.issue_counter += 1

            # Priority based on complexity
            if complexity >= 20:
                priority = Priority.CRITICAL
            elif complexity >= 15:
                priority = Priority.HIGH
            else:
                priority = Priority.MEDIUM

            func_name = func_data.get("name", "unknown")
            issue = Issue(
                id=f"RAD-{self.issue_counter:04d}",
                priority=priority,
                category=Category.COMPLEXITY,
                source="radon",
                file=file_path,
                line=func_data.get("lineno"),
                message=(
                    f"Function '{func_name}' has complexity {complexity} "
                    f"(target: ≤10)"
                ),
                details=f"Cyclomatic complexity: {complexity}",
                fix="Extract sub-functions to reduce complexity",
            )
            self._add_issue(issue)

    def _run_black(self):
        """Run black formatter check"""
        print("  → Running black (formatting)...", file=sys.stderr)
        try:
            result = subprocess.run(  # nosec B603
                [LINTER_PATHS["black"], str(self.path), "--check", "--diff"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # Black returns non-zero if formatting needed
            if result.returncode != 0 and result.stdout:
                # Count files that need formatting
                files_needing_format = len(
                    [
                        line
                        for line in result.stdout.split("\n")
                        if line.startswith("would reformat")
                    ]
                )

                if files_needing_format > 0:
                    self.issue_counter += 1

                    issue = Issue(
                        id=f"BLK-{self.issue_counter:04d}",
                        priority=Priority.LOW,  # Formatting is low priority
                        category=Category.FORMATTING,
                        source="black",
                        file=str(self.path),
                        line=None,
                        message=f"{files_needing_format} file(s) need formatting",
                        details="Code formatting does not match Black style",
                        fix=f"Run: {LINTER_PATHS['black']} {self.path}",
                    )
                    self._add_issue(issue)

            self.linters_run.append("black")
            issue_count = len([i for i in self.issues if i.source == "black"])
            print(f"    ✓ black: {issue_count} issues found", file=sys.stderr)

        except subprocess.TimeoutExpired:
            print("    ✗ black timed out", file=sys.stderr)
            self.linters_failed.append("black")
        except (RuntimeError, OSError) as e:
            if self.verbose:
                print(f"    ✗ black failed: {e}", file=sys.stderr)
            self.linters_failed.append("black")

    def _has_pytest_config(self) -> bool:
        """Check if pytest is configured"""
        return (
            (self.path / "tests").exists()
            or (self.path / "test").exists()
            or (self.path / "pytest.ini").exists()
        )

    def _parse_coverage_data(self, coverage_file: Path) -> Optional[float]:
        """Parse coverage percentage from coverage.json"""
        try:
            with open(coverage_file, encoding="utf-8") as f:
                data = json.load(f)
            return data["totals"]["percent_covered"]
        except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
            if self.verbose:
                print(f"    ✗ pytest coverage parse error: {e}")
            self.linters_failed.append("pytest")
            return None

    def _create_coverage_issue(self, total_coverage: float) -> None:
        """Create issue for low test coverage"""
        self.issue_counter += 1

        if total_coverage < 50:
            priority = Priority.CRITICAL
        elif total_coverage < 70:
            priority = Priority.HIGH
        else:
            priority = Priority.MEDIUM

        issue = Issue(
            id=f"COV-{self.issue_counter:04d}",
            priority=priority,
            category=Category.TESTING,
            source="pytest",
            file="Overall",
            line=None,
            message=f"Test coverage is {total_coverage:.1f}% (target: ≥80%)",
            details=f"Missing coverage: {100 - total_coverage:.1f}%",
            fix="Add unit tests for uncovered code",
        )
        self._add_issue(issue)

    def _run_pytest(self):
        """Run pytest coverage check"""
        print("  → Running pytest (coverage)...", file=sys.stderr)
        try:
            if not self._has_pytest_config():
                if self.verbose:
                    print(
                        "    → No tests directory found, skipping pytest",
                        file=sys.stderr,
                    )
                self.linters_run.append("pytest")
                return

            subprocess.run(  # nosec B603
                [
                    LINTER_PATHS["pytest"],
                    "--cov=.",
                    "--cov-report=json",
                    "--quiet",
                    "--tb=no",
                ],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=self.path,
                check=False,
            )

            coverage_file = self.path / "coverage.json"
            if coverage_file.exists():
                total_coverage = self._parse_coverage_data(coverage_file)
                if total_coverage is None:
                    return

                if total_coverage < 80:
                    self._create_coverage_issue(total_coverage)

                coverage_file.unlink(missing_ok=True)

            self.linters_run.append("pytest")
            issue_count = len([i for i in self.issues if i.source == "pytest"])
            print(f"    ✓ pytest: {issue_count} issues found", file=sys.stderr)

        except subprocess.TimeoutExpired:
            print("    ✗ pytest timed out", file=sys.stderr)
            self.linters_failed.append("pytest")
        except (RuntimeError, OSError) as e:
            if self.verbose:
                print(f"    ✗ pytest failed: {e}", file=sys.stderr)
            self.linters_failed.append("pytest")

    def _suggest_security_fix(self, test_id: str) -> str:
        """Suggest fix based on bandit test ID"""
        fixes = {
            "B105": "Use secrets module or environment variables instead of hardcoded passwords",
            "B106": "Move secrets to secure configuration or environment variables",
            "B107": "Move secrets to secure configuration or environment variables",
            "B201": "Use parameterized queries or an ORM to prevent SQL injection",
            "B301": "Use yaml.safe_load() instead of yaml.load()",
            "B302": "Use defusedxml for XML parsing",
            "B303": "Avoid using MD5 for security. Use SHA-256 or better",
            "B304": "Avoid using insecure cipher modes",
            "B305": "Avoid using insecure cipher",
            "B306": "Use mkstemp() instead of mktemp()",
            "B307": "Use defusedxml.lxml for parsing XML",
            "B308": "Use defusedxml.lxml for parsing XML",
            "B309": "Use defusedxml.lxml for parsing XML",
            "B310": "Audit URL open for permitted schemes",
            "B311": "Use secrets module for cryptographically secure random numbers",
            "B312": "Use secrets.token_hex() for secure tokens",
            "B313": "Use xml.etree.ElementTree.XMLParser with appropriate settings",
            "B314": "Use xml.etree.ElementTree.XMLParser with appropriate settings",
            "B315": "Use xml.etree.ElementTree.XMLParser with appropriate settings",
            "B316": "Use xml.etree.ElementTree.XMLParser with appropriate settings",
            "B317": "Use xml.etree.ElementTree.XMLParser with appropriate settings",
            "B318": "Use xml.etree.ElementTree.XMLParser with appropriate settings",
            "B319": "Use xml.etree.ElementTree.XMLParser with appropriate settings",
            "B320": "Use xml.etree.ElementTree.XMLParser with appropriate settings",
            "B321": "Use ftplib with caution, prefer SFTP",
            "B322": "Avoid using input() in Python 2",
            "B323": "Avoid unverified context in SSL/TLS",
            "B324": "Use hashlib with secure algorithms",
            "B325": "Avoid using tempfile.mktemp()",
            "B401": "Use subprocess instead of os.popen",
            "B402": "Use subprocess instead of os.popen",
            "B403": "Consider implications of importing pickle",
            "B404": "Consider implications of importing subprocess",
            "B405": "Consider implications of importing xml.etree",
            "B406": "Consider implications of importing xml.sax",
            "B407": "Consider implications of importing xml.expat",
            "B408": "Consider implications of importing xml.minidom",
            "B409": "Consider implications of importing xml.pulldom",
            "B410": "Consider implications of importing lxml",
            "B411": "Consider implications of importing xmlrpclib",
            "B412": "Consider implications of importing httpoxy",
            "B413": "Consider implications of importing pyCrypto",
            "B501": "Disable certificate verification cautiously",
            "B502": "Use verify=True for SSL/TLS connections",
            "B503": "Use verify=True for SSL/TLS connections",
            "B504": "Use verify=True for SSL/TLS connections",
            "B505": "Avoid weak cryptographic key",
            "B506": "Avoid yaml.load(), use yaml.safe_load()",
            "B507": "Avoid ssh with shell=True",
            "B601": "Avoid shell=True in subprocess",
            "B602": "Avoid shell=True in popen",
            "B603": "Avoid untrusted input in subprocess",
            "B604": "Avoid shell=True in calls",
            "B605": "Avoid starting process with shell",
            "B606": "Avoid starting process with no shell",
            "B607": "Specify full path to executable or validate input",
            "B608": "Possible SQL injection",
            "B609": "Use parameterized queries",
            "B610": "Use parameterized queries with django",
            "B611": "Use parameterized queries with django",
            "B701": "Consider using jinja2.select_autoescape",
            "B702": "Consider using jinja2.select_autoescape",
            "B703": "Consider using jinja2.select_autoescape",
        }
        return fixes.get(test_id, "Review security best practices for this issue")

    def _sort_issues_by_priority(self) -> None:
        """Sort issues by priority (Critical first)"""
        priority_order = {
            Priority.CRITICAL: 0,
            Priority.HIGH: 1,
            Priority.MEDIUM: 2,
            Priority.LOW: 3,
            Priority.INFO: 4,
        }
        self.issues.sort(
            key=lambda x: (priority_order.get(x.priority, 5), x.file, x.line or 0)
        )

    def _count_issues_by_priority(self) -> Tuple[int, int, int, int, int]:
        """Count issues by priority level"""
        priorities = [
            Priority.CRITICAL,
            Priority.HIGH,
            Priority.MEDIUM,
            Priority.LOW,
            Priority.INFO,
        ]
        counts = [len([i for i in self.issues if i.priority == p]) for p in priorities]
        return tuple(counts)

    def _count_issues_by_category(self) -> Dict[str, int]:
        """Count issues by category"""
        issues_by_category = {}
        for category in Category:
            count = len([i for i in self.issues if i.category == category])
            if count > 0:
                issues_by_category[category.value] = count
        return issues_by_category

    def _aggregate(self, execution_time: float) -> AggregatedResult:
        """Aggregate all issues"""
        self._sort_issues_by_priority()
        critical, high, medium, low, info = self._count_issues_by_priority()
        issues_by_category = self._count_issues_by_category()

        summary = self._generate_summary(
            len(self.issues), critical, high, medium, low, info
        )

        status = "completed_with_failures" if self.linters_failed else "completed"

        return AggregatedResult(
            status=status,
            total_issues=len(self.issues),
            critical_issues=critical,
            high_issues=high,
            medium_issues=medium,
            low_issues=low,
            info_issues=info,
            issues_by_category=issues_by_category,
            issues=self.issues,
            linters_run=self.linters_run,
            linters_failed=self.linters_failed,
            execution_time_seconds=round(execution_time, 2),
            summary=summary,
        )

    def _generate_summary(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, total: int, critical: int, high: int, medium: int, low: int, info: int
    ) -> str:
        """Generate human-readable summary"""
        if total == 0:
            return "✅ No issues found. All linters passed."

        parts = [f"Found {total} issue{'s' if total != 1 else ''}:"]
        if critical > 0:
            parts.append(f"🔴 {critical} critical (P0)")
        if high > 0:
            parts.append(f"🟡 {high} high (P1)")
        if medium > 0:
            parts.append(f"🟠 {medium} medium (P2)")
        if low > 0:
            parts.append(f"⚪ {low} low (P3)")
        if info > 0:
            parts.append(f"ℹ️  {info} info (P4)")

        if critical > 0:
            parts.append("⚠️  Critical issues must be fixed immediately.")
        elif high > 0:
            parts.append("⚠️  High-priority issues should be fixed soon.")

        return " | ".join(parts)


def main():  # pylint: disable=too-many-branches
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Roger Linter Aggregator - Production Implementation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Run in current directory
  %(prog)s --path src/              # Run in specific directory
  %(prog)s --format text            # Human-readable output
  %(prog)s --verbose                # Verbose output
  %(prog)s --no-parallel            # Disable parallel execution
        """,
    )
    parser.add_argument(
        "--path", default=".", help="Path to analyze (default: current directory)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "--no-parallel", action="store_true", help="Disable parallel execution"
    )
    args = parser.parse_args()

    try:
        # Run aggregator
        aggregator = LinterAggregator(
            path=args.path, verbose=args.verbose, parallel=not args.no_parallel
        )
        result = aggregator.run_all()

        # Output results
        if args.format == "json":
            print("\n" + "=" * 80)
            print("LINTER AGGREGATOR RESULTS (JSON)")
            print("=" * 80)
            print(json.dumps(result.to_dict(), indent=2))
        else:
            # Text format
            print("\n" + "=" * 80)
            print("LINTER AGGREGATOR RESULTS")
            print("=" * 80)
            print(f"\n{result.summary}\n")
            print(f"Execution time: {result.execution_time_seconds}s")
            print(f"Linters run: {', '.join(result.linters_run)}")
            if result.linters_failed:
                print(f"⚠️  Linters failed: {', '.join(result.linters_failed)}")

            if result.issues:
                print("\nIssues by Category:")
                for category, count in sorted(result.issues_by_category.items()):
                    print(f"  {category}: {count}")

                print("\nDetailed Issues:\n")
                for issue in result.issues:
                    print(
                        f"{issue.priority.value} [{issue.source}] {issue.file}:{issue.line or '?'}"
                    )
                    print(f"  {issue.message}")
                    if issue.fix:
                        print(f"  💡 Fix: {issue.fix}")
                    print()

        # Exit code
        # 0 = success (no critical/high issues)
        # 1 = issues found (critical or high)
        # 2 = linters failed
        if result.linters_failed:
            sys.exit(2)
        elif result.critical_issues > 0 or result.high_issues > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except SecurityError as e:
        print(f"\n❌ Security Error: {e}", file=sys.stderr)
        sys.exit(2)
    except (RuntimeError, OSError, ValueError) as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
