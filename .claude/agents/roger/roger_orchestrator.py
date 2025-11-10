#!/usr/bin/env python3
"""
Roger Orchestrator - Production Implementation.

Central orchestration layer for POC4 CodeRabbit integration (Path A).
Coordinates Layer 1 (linter aggregator) and Layer 3 (CodeRabbit) analysis,
deduplicates findings, normalizes output, and creates defect logs.

This module is the main entry point for Roger analysis. It orchestrates the
execution of Layer 1 (linter aggregator) and optionally Layer 3 (CodeRabbit),
applies deduplication logic, normalizes findings to Roger format, and generates
Markdown defect logs.

Features:
- Layer 1 integration (6 Python linters: bandit, pylint, mypy, radon, black,
pytest)
- Layer 3 integration (CodeRabbit AI - stubbed in Phase 2)
- Fingerprint-based deduplication with Layer 1 precedence
- Output normalization to unified Roger format
- Defect log generation in Markdown format
- Comprehensive error handling with graceful degradation
- Performance tracking and execution metrics

Key Classes:
    - RogerOrchestrator: Main orchestration class

Key Functions:
    - roger_orchestrator: Convenience function for one-shot analysis

Usage:
    from roger_orchestrator import roger_orchestrator

    # Run analysis on a directory
    result = roger_orchestrator(
        file_paths=['/srv/cc/my-project'],
        project_name="My Project",
        verbose=True
    )

    # Check results
    print(f"Total issues: {result['summary']['total_issues']}")
    print(f"Defect log: {result['defect_log_path']}")

See Also:
    - finding_utils.py: Finding deduplication and normalization
    - defect_logger.py: Defect log generation
    - layer3_stub.py: Layer 3 stub (Phase 2)

Author: Eric Johnson (Senior Developer)
Date: 2025-11-10
Version: 1.0
Layer: POC4 CodeRabbit Layer 2 (Orchestration)
"""

import sys
import time
import subprocess  # nosec B404  # pylint: disable=unused-import
import json
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass

# Import Roger components
from layer3_stub import CodeRabbitLayer3
from defect_logger import DefectLogger
from finding_utils import deduplicate_findings, normalize_findings, generate_summary

# Import Layer 1 linter aggregator
# Note: linter_aggregator.py will be made importable in next step
try:
    from linter_aggregator import LinterAggregator
except ImportError:
    # Fallback: Run as subprocess (temporary solution for Phase 2)
    LinterAggregator = None


@dataclass
class RogerConfig:
    """Configuration for Roger orchestrator"""

    project_name: str = "Unknown Project"
    enable_layer3: bool = False
    defect_log_path: str = "./DEFECT-LOG.md"
    verbose: bool = False
    json_format: bool = False


class RogerOrchestrator:  # pylint: disable=too-few-public-methods
    """
    Roger orchestrator: Coordinates Layer 1 + Layer 3 analysis.

    Manages the complete analysis workflow including running linters,
    optionally calling CodeRabbit, deduplicating findings, normalizing
    output, and generating defect logs.

    Responsibilities:
    - Call Layer 1 (linter aggregator) - always runs
    - Call Layer 3 (CodeRabbit) - optional, Phase 2 stubbed
    - Deduplicate findings using Layer 1 precedence rules
    - Normalize output to unified Roger format
    - Create defects in Markdown defect log
    - Track execution metrics and performance

    Attributes:
        project_name: Project name for defect tracking
        enable_layer3: Whether Layer 3 (CodeRabbit) is enabled
        defect_log_path: Path to defect log file
        verbose: Whether verbose output is enabled
        layer3: Layer 3 instance (if enabled)
        defect_logger: Defect logger instance

    Examples:
        >>> orchestrator = RogerOrchestrator(
        ...     project_name="My Project",
        ...     verbose=True
        ... )
        >>> result = orchestrator.analyze(['/srv/cc/my-project'])
        >>> result['status']
        'success'
    """

    def __init__(self, roger_config: RogerConfig):
        """
        Initialize Roger orchestrator.

        Args:
            roger_config: RogerConfig instance with all configuration settings
        """
        self.config = roger_config

        # Initialize components
        self.layer3 = CodeRabbitLayer3() if roger_config.enable_layer3 else None
        self.defect_logger = DefectLogger(roger_config.defect_log_path)

    @property
    def project_name(self) -> str:
        """Get project name from config"""
        return self.config.project_name

    @property
    def enable_layer3(self) -> bool:
        """Get enable_layer3 from config"""
        return self.config.enable_layer3

    @property
    def defect_log_path(self) -> str:
        """Get defect_log_path from config"""
        return self.config.defect_log_path

    @property
    def verbose(self) -> bool:
        """Get verbose from config"""
        return self.config.verbose

    @property
    def json_format(self) -> bool:
        """Get json_format from config"""
        return self.config.json_format

    def _print_analysis_start(self, file_paths: List[str]) -> None:
        """Print analysis start information"""
        if self.verbose:
            output_file = sys.stderr if self.json_format else sys.stdout
            print("🔍 Roger Orchestrator - Starting analysis", file=output_file)
            print(f"  Project: {self.project_name}", file=output_file)
            print(f"  Files: {len(file_paths)}", file=output_file)
            print(
                f"  Layer 3: {'Enabled' if self.enable_layer3 else 'Disabled'}",
                file=output_file,
            )
            print(file=output_file)

    def _deduplicate_and_normalize(
        self, layer1_findings: List[Dict], layer3_findings: List[Dict]
    ) -> List[Dict]:
        """Deduplicate and normalize findings"""
        if self.verbose:
            output_file = sys.stderr if self.json_format else sys.stdout
            print("🔀 Deduplicating findings...", file=output_file)
            print(f"  Layer 1: {len(layer1_findings)} findings", file=output_file)
            print(f"  Layer 3: {len(layer3_findings)} findings", file=output_file)

        all_findings = deduplicate_findings(layer1_findings, layer3_findings)

        if self.verbose:
            output_file = sys.stderr if self.json_format else sys.stdout
            print(f"  Deduplicated: {len(all_findings)} findings", file=output_file)
            print(file=output_file)
            print("✨ Normalizing findings to Roger format...", file=output_file)

        normalized = normalize_findings(all_findings)

        if self.verbose:
            output_file = sys.stderr if self.json_format else sys.stdout
            print(f"  Normalized: {len(normalized)} findings", file=output_file)
            print(file=output_file)

        return normalized

    def _create_defect_log_with_output(self, normalized_findings: List[Dict]) -> int:
        """Create defect log with verbose output"""
        if self.verbose:
            output_file = sys.stderr if self.json_format else sys.stdout
            print("📝 Creating defect log...", file=output_file)

        defects_created = self.defect_logger.create_defect_log(
            normalized_findings, self.project_name, overwrite=True
        )

        if self.verbose:
            output_file = sys.stderr if self.json_format else sys.stdout
            print(f"  Defects logged: {defects_created}", file=output_file)
            print(f"  Log path: {self.defect_log_path}", file=output_file)
            print(file=output_file)

        return defects_created

    def analyze(self, file_paths: List[str]) -> Dict:
        """
        Analyze files with Layer 1 + optionally Layer 3.

        Orchestrates the complete analysis workflow:
        1. Run Layer 1 linter aggregator
        2. Optionally run Layer 3 CodeRabbit (if enabled)
        3. Deduplicate findings (Layer 1 precedence)
        4. Normalize to Roger format
        5. Generate summary statistics
        6. Create defect log

        Args:
            file_paths: List of file paths or directories to analyze

        Returns:
            Dictionary with analysis results:
                - findings: List of deduplicated, normalized findings
                - summary: Counts by category, priority, layer
                - defects_created: Number of defects logged
                - execution_time: Total time in seconds
                - layers_used: ["layer1"] or ["layer1", "layer3"]
                - status: "success" or "partial_failure"
                - project_name: Project name
                - defect_log_path: Path to generated defect log

        Examples:
            >>> orchestrator = RogerOrchestrator("My Project")
            >>> result = orchestrator.analyze(['/srv/cc/project'])
            >>> print(f"Found {result['summary']['total_issues']} issues")
        """
        start_time = time.time()
        self._print_analysis_start(file_paths)

        # Run layers
        layer1_findings, layer1_success = self._run_layer1(file_paths)
        layer3_findings = []
        if self.enable_layer3 and self.layer3:
            layer3_findings = self._run_layer3(file_paths)

        # Process findings
        normalized_findings = self._deduplicate_and_normalize(
            layer1_findings, layer3_findings
        )
        summary = generate_summary(normalized_findings)
        defects_created = self._create_defect_log_with_output(normalized_findings)

        # Build result
        execution_time = time.time() - start_time
        layers_used = ["layer1"]
        if self.enable_layer3 and len(layer3_findings) > 0:
            layers_used.append("layer3")

        status = "success" if layer1_success else "partial_failure"

        if self.verbose:
            output_file = sys.stderr if self.json_format else sys.stdout
            print("✅ Analysis complete", file=output_file)
            print(f"  {summary['summary_text']}", file=output_file)
            print(f"  Execution time: {execution_time:.2f}s", file=output_file)
            print(file=output_file)

        return {
            "findings": normalized_findings,
            "summary": summary,
            "defects_created": defects_created,
            "execution_time": round(execution_time, 2),
            "layers_used": layers_used,
            "status": status,
            "project_name": self.project_name,
            "defect_log_path": str(self.defect_log_path),
        }

    def _determine_analysis_path(self, file_paths: List[str]) -> str:
        """Determine the path to analyze from file paths"""
        if not file_paths:
            return "."
        if len(file_paths) == 1:
            return file_paths[0]
        # Multiple files - analyze their common parent directory
        return str(Path(file_paths[0]).parent)

    def _run_layer1_direct_import(self, analysis_path: str) -> Tuple[List[Dict], bool]:
        """Run Layer 1 using direct import"""
        aggregator = LinterAggregator(
            path=analysis_path, verbose=self.verbose, parallel=True
        )
        aggregator_result = aggregator.run_all()

        # Extract issues from AggregatedResult
        layer1_findings = [issue.to_dict() for issue in aggregator_result.issues]

        if self.verbose:
            output_file = sys.stderr if self.json_format else sys.stdout
            print(
                f"  ✓ Layer 1 complete: {len(layer1_findings)} issues",
                file=output_file,
            )
            print(file=output_file)

        return layer1_findings, True

    def _run_layer1_subprocess(self, analysis_path: str) -> Tuple[List[Dict], bool]:
        """Run Layer 1 using subprocess fallback"""
        linter_path = Path(__file__).parent / "linter_aggregator.py"

        subprocess_result = subprocess.run(  # nosec B603
            [
                sys.executable,
                str(linter_path),
                "--path",
                analysis_path,
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )

        # 0 = clean, 1 = issues found
        if subprocess_result.returncode in [0, 1]:
            data = json.loads(subprocess_result.stdout)
            layer1_findings = data.get("issues", [])

            if self.verbose:
                output_file = sys.stderr if self.json_format else sys.stdout
                layer1_count = len(layer1_findings)
                print(f"  ✓ Layer 1 complete: {layer1_count} issues", file=output_file)
                print(file=output_file)

            return layer1_findings, True

        if self.verbose:
            output_file = sys.stderr if self.json_format else sys.stdout
            print(
                f"  ⚠️  Layer 1 failed (exit code {subprocess_result.returncode})",
                file=output_file,
            )
            if subprocess_result.stderr:
                print(f"  Error: {subprocess_result.stderr}", file=output_file)
            print(file=output_file)

        return [], False

    def _run_layer1(self, file_paths: List[str]) -> Tuple[List[Dict], bool]:
        """
        Run Layer 1 linter aggregator.

        Executes the linter aggregator (bandit, pylint, mypy, radon, black,
        pytest) on the specified file paths. Attempts direct import first,
        falls back to subprocess execution if import fails.

        Args:
            file_paths: List of file paths or directories to analyze

        Returns:
            Tuple of (findings, success_flag):
                - findings: List of findings from Layer 1 linters
                - success_flag: True if execution succeeded, False if failed

        Examples:
            >>> orchestrator = RogerOrchestrator()
            >>> findings, success = orchestrator._run_layer1(['/srv/cc/project'])
            >>> success
            True
            >>> len(findings) > 0
            True
        """
        if self.verbose:
            output_file = sys.stderr if self.json_format else sys.stdout
            print("🔧 Running Layer 1 (Linter Aggregator)...", file=output_file)

        analysis_path = self._determine_analysis_path(file_paths)

        try:
            if LinterAggregator:
                return self._run_layer1_direct_import(analysis_path)
            return self._run_layer1_subprocess(analysis_path)

        except (subprocess.TimeoutExpired, RuntimeError, OSError) as e:
            if self.verbose:
                output_file = sys.stderr if self.json_format else sys.stdout
                print(f"  ✗ Layer 1 exception: {e}", file=output_file)
                print(file=output_file)
            return [], False

    def _run_layer3(self, file_paths: List[str]) -> List[Dict]:
        """
        Run Layer 3 CodeRabbit analysis.

        Executes CodeRabbit AI analysis on the specified file paths.
        In Phase 2, this is stubbed and returns empty list.

        Args:
            file_paths: List of file paths to analyze

        Returns:
            List of findings from CodeRabbit (empty in Phase 2 stub)

        Examples:
            >>> orchestrator = RogerOrchestrator(enable_layer3=True)
            >>> findings = orchestrator._run_layer3(['/srv/cc/test.py'])
            >>> findings
            []
        """
        if self.verbose:
            output_file = sys.stderr if self.json_format else sys.stdout
            print("🤖 Running Layer 3 (CodeRabbit)...", file=output_file)

        try:
            findings = self.layer3.analyze_files(file_paths)

            if self.verbose:
                output_file = sys.stderr if self.json_format else sys.stdout
                print(f"  ✓ Layer 3 complete: {len(findings)} issues", file=output_file)
                print(file=output_file)

            return findings

        except (RuntimeError, OSError, ValueError) as e:
            if self.verbose:
                output_file = sys.stderr if self.json_format else sys.stdout
                print(f"  ✗ Layer 3 exception: {e}", file=output_file)
                print(file=output_file)
            return []


def roger_orchestrator(
    file_paths: List[str], roger_config: RogerConfig = None, **kwargs
) -> Dict:
    """
    Convenience function to run Roger orchestrator.

    Creates a RogerOrchestrator instance and runs analysis in a single call.
    Useful for one-shot analysis without managing orchestrator lifecycle.

    Args:
        file_paths: List of file paths or directories to analyze
        roger_config: RogerConfig instance (if None, kwargs will be used)
        **kwargs: Individual config parameters (used if roger_config is None)
            - project_name: Project name for defect tracking
            - enable_layer3: Enable CodeRabbit Layer 3 (default: False)
            - defect_log_path: Path to defect log file (default: ./DEFECT-LOG.md)
            - verbose: Enable verbose output (default: False)
            - json_format: If True, send all output to stderr (default: False)

    Returns:
        Dictionary with analysis results (see RogerOrchestrator.analyze)

    Examples:
        >>> result = roger_orchestrator(
        ...     file_paths=['/srv/cc/my-project'],
        ...     project_name="My Project",
        ...     verbose=True
        ... )
        >>> print(f"Total issues: {result['summary']['total_issues']}")
    """
    if roger_config is None:
        roger_config = RogerConfig(**kwargs)

    orchestrator = RogerOrchestrator(roger_config=roger_config)
    return orchestrator.analyze(file_paths)


# Example usage
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Roger Orchestrator - Layer 1 + Layer 3 Code Analysis"
    )
    parser.add_argument(
        "--path", nargs="+", default=["."], help="File paths or directories to analyze"
    )
    parser.add_argument(
        "--project", default="Unknown Project", help="Project name for defect tracking"
    )
    parser.add_argument(
        "--enable-layer3",
        action="store_true",
        help="Enable CodeRabbit Layer 3 (default: disabled)",
    )
    parser.add_argument(
        "--defect-log", default="./DEFECT-LOG.md", help="Path to defect log file"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "--format", choices=["json", "text"], default="text", help="Output format"
    )

    args = parser.parse_args()

    # Create config
    config = RogerConfig(
        project_name=args.project,
        enable_layer3=args.enable_layer3,
        defect_log_path=args.defect_log,
        verbose=args.verbose,
        json_format=(args.format == "json"),
    )

    # Run orchestrator
    result = roger_orchestrator(file_paths=args.path, roger_config=config)

    # Output results
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("=" * 80)
        print("ROGER ORCHESTRATOR RESULTS")
        print("=" * 80)
        print()
        print(f"Project: {result['project_name']}")
        print(f"Status: {result['status']}")
        print(f"Execution time: {result['execution_time']}s")
        print(f"Layers used: {', '.join(result['layers_used'])}")
        print()
        print(f"Summary: {result['summary']['summary_text']}")
        print()
        print(f"Defects created: {result['defects_created']}")
        print(f"Defect log: {result['defect_log_path']}")
        print()

    # Exit code
    # 0 = success (no critical/high issues)
    # 1 = issues found (critical or high)
    # 2 = execution error
    if result["status"] != "success":
        sys.exit(2)
    elif (
        result["summary"]["by_priority"]["P0"] > 0
        or result["summary"]["by_priority"]["P1"] > 0
    ):
        sys.exit(1)
    else:
        sys.exit(0)
