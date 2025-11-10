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
from pathlib import Path
from typing import Dict, List

# Import Roger components
from layer3_stub import CodeRabbitLayer3
from defect_logger import DefectLogger
from finding_utils import (
    deduplicate_findings,
    normalize_findings,
    generate_summary
)

# Import Layer 1 linter aggregator
# Note: linter_aggregator.py will be made importable in next step
try:
    from linter_aggregator import LinterAggregator
except ImportError:
    # Fallback: Run as subprocess (temporary solution for Phase 2)
    LinterAggregator = None


class RogerOrchestrator:
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

    def __init__(
        self,
        project_name: str = "Unknown Project",
        enable_layer3: bool = False,
        defect_log_path: str = "./DEFECT-LOG.md",
        verbose: bool = False
    ):
        """
        Initialize Roger orchestrator.

        Args:
            project_name: Project name for defect tracking
            enable_layer3: Enable CodeRabbit Layer 3 (default: False,
                stubbed in Phase 2)
            defect_log_path: Path to defect log file
                (default: ./DEFECT-LOG.md)
            verbose: Enable verbose output (default: False)
        """
        self.project_name = project_name
        self.enable_layer3 = enable_layer3
        self.defect_log_path = defect_log_path
        self.verbose = verbose

        # Initialize components
        self.layer3 = CodeRabbitLayer3() if enable_layer3 else None
        self.defect_logger = DefectLogger(defect_log_path)

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

        if self.verbose:
            print("🔍 Roger Orchestrator - Starting analysis")
            print(f"  Project: {self.project_name}")
            print(f"  Files: {len(file_paths)}")
            print(f"  Layer 3: {'Enabled' if self.enable_layer3 else 'Disabled'}")
            print()

        # Phase 1: Run Layer 1 (linter aggregator)
        layer1_findings = self._run_layer1(file_paths)

        # Phase 2: Run Layer 3 (CodeRabbit) if enabled
        layer3_findings = []
        if self.enable_layer3 and self.layer3:
            layer3_findings = self._run_layer3(file_paths)

        # Phase 3: Deduplicate findings
        if self.verbose:
            print("🔀 Deduplicating findings...")
            print(f"  Layer 1: {len(layer1_findings)} findings")
            print(f"  Layer 3: {len(layer3_findings)} findings")

        all_findings = deduplicate_findings(layer1_findings, layer3_findings)

        if self.verbose:
            print(f"  Deduplicated: {len(all_findings)} findings")
            print()

        # Phase 4: Normalize output
        if self.verbose:
            print("✨ Normalizing findings to Roger format...")

        normalized_findings = normalize_findings(all_findings)

        if self.verbose:
            print(f"  Normalized: {len(normalized_findings)} findings")
            print()

        # Phase 5: Generate summary
        summary = generate_summary(normalized_findings)

        # Phase 6: Create defects in defect log
        if self.verbose:
            print("📝 Creating defect log...")

        defects_created = self.defect_logger.create_defect_log(
            normalized_findings,
            self.project_name,
            overwrite=True
        )

        if self.verbose:
            print(f"  Defects logged: {defects_created}")
            print(f"  Log path: {self.defect_log_path}")
            print()

        # Calculate execution time
        execution_time = time.time() - start_time

        # Determine layers used
        layers_used = ['layer1']
        if self.enable_layer3 and len(layer3_findings) > 0:
            layers_used.append('layer3')

        # Determine status
        status = "success"
        if len(layer1_findings) == 0:
            status = "partial_failure"  # Layer 1 failed to produce results

        # Generate result
        result = {
            'findings': normalized_findings,
            'summary': summary,
            'defects_created': defects_created,
            'execution_time': round(execution_time, 2),
            'layers_used': layers_used,
            'status': status,
            'project_name': self.project_name,
            'defect_log_path': str(self.defect_log_path)
        }

        if self.verbose:
            print("✅ Analysis complete")
            print(f"  {summary['summary_text']}")
            print(f"  Execution time: {execution_time:.2f}s")
            print()

        return result

    def _run_layer1(self, file_paths: List[str]) -> List[Dict]:
        """
        Run Layer 1 linter aggregator.

        Executes the linter aggregator (bandit, pylint, mypy, radon, black,
        pytest) on the specified file paths. Attempts direct import first,
        falls back to subprocess execution if import fails.

        Args:
            file_paths: List of file paths or directories to analyze

        Returns:
            List of findings from Layer 1 linters (empty list on error)

        Examples:
            >>> orchestrator = RogerOrchestrator()
            >>> findings = orchestrator._run_layer1(['/srv/cc/project'])
            >>> len(findings) > 0
            True
        """
        if self.verbose:
            print("🔧 Running Layer 1 (Linter Aggregator)...")

        # Determine path to analyze
        # If multiple paths, analyze first one (simple implementation for Phase 2)
        # Phase 3 could support multi-path analysis
        if not file_paths:
            analysis_path = "."
        elif len(file_paths) == 1:
            analysis_path = file_paths[0]
        else:
            # Multiple files - analyze their common parent directory
            analysis_path = str(Path(file_paths[0]).parent)

        try:
            if LinterAggregator:
                # Direct import available
                aggregator = LinterAggregator(
                    path=analysis_path,
                    verbose=self.verbose,
                    parallel=True
                )
                result = aggregator.run_all()

                # Extract issues from AggregatedResult
                layer1_findings = [issue.to_dict() for issue in result.issues]

                if self.verbose:
                    print(f"  ✓ Layer 1 complete: {len(layer1_findings)} issues")
                    print()

                return layer1_findings

            else:
                # Fallback: Run as subprocess
                import subprocess
                import json

                linter_path = Path(__file__).parent / 'linter_aggregator.py'

                result = subprocess.run(
                    [
                        sys.executable,
                        str(linter_path),
                        '--path',
                        analysis_path,
                        '--format',
                        'json'
                    ],
                    capture_output=True,
                    text=True,
                    timeout=600
                )

                # 0 = clean, 1 = issues found
                if result.returncode in [0, 1]:
                    data = json.loads(result.stdout)
                    layer1_findings = data.get('issues', [])

                    if self.verbose:
                        layer1_count = len(layer1_findings)
                        print(f"  ✓ Layer 1 complete: {layer1_count} issues")
                        print()

                    return layer1_findings
                else:
                    if self.verbose:
                        rc = result.returncode
                        print(f"  ✗ Layer 1 failed with exit code {rc}")
                        print()
                    return []

        except Exception as e:
            if self.verbose:
                print(f"  ✗ Layer 1 exception: {e}")
                print()
            return []

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
            print("🤖 Running Layer 3 (CodeRabbit)...")

        try:
            findings = self.layer3.analyze_files(file_paths)

            if self.verbose:
                print(f"  ✓ Layer 3 complete: {len(findings)} issues")
                print()

            return findings

        except Exception as e:
            if self.verbose:
                print(f"  ✗ Layer 3 exception: {e}")
                print()
            return []


def roger_orchestrator(
    file_paths: List[str],
    project_name: str = "Unknown Project",
    enable_layer3: bool = False,
    defect_log_path: str = "./DEFECT-LOG.md",
    verbose: bool = False
) -> Dict:
    """
    Convenience function to run Roger orchestrator.

    Creates a RogerOrchestrator instance and runs analysis in a single call.
    Useful for one-shot analysis without managing orchestrator lifecycle.

    Args:
        file_paths: List of file paths or directories to analyze
        project_name: Project name for defect tracking
        enable_layer3: Enable CodeRabbit Layer 3 (default: False)
        defect_log_path: Path to defect log file (default: ./DEFECT-LOG.md)
        verbose: Enable verbose output (default: False)

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
    orchestrator = RogerOrchestrator(
        project_name=project_name,
        enable_layer3=enable_layer3,
        defect_log_path=defect_log_path,
        verbose=verbose
    )

    return orchestrator.analyze(file_paths)


# Example usage
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Roger Orchestrator - Layer 1 + Layer 3 Code Analysis'
    )
    parser.add_argument(
        '--path',
        nargs='+',
        default=['.'],
        help='File paths or directories to analyze'
    )
    parser.add_argument(
        '--project',
        default='Unknown Project',
        help='Project name for defect tracking'
    )
    parser.add_argument(
        '--enable-layer3',
        action='store_true',
        help='Enable CodeRabbit Layer 3 (default: disabled)'
    )
    parser.add_argument(
        '--defect-log',
        default='./DEFECT-LOG.md',
        help='Path to defect log file'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'text'],
        default='text',
        help='Output format'
    )

    args = parser.parse_args()

    # Run orchestrator
    result = roger_orchestrator(
        file_paths=args.path,
        project_name=args.project,
        enable_layer3=args.enable_layer3,
        defect_log_path=args.defect_log,
        verbose=args.verbose
    )

    # Output results
    if args.format == 'json':
        import json
        print(json.dumps(result, indent=2))
    else:
        print("="*80)
        print("ROGER ORCHESTRATOR RESULTS")
        print("="*80)
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
    if result['status'] != 'success':
        sys.exit(2)
    elif result['summary']['by_priority']['P0'] > 0 or result['summary']['by_priority']['P1'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)
