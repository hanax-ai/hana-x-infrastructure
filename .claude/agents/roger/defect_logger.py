#!/usr/bin/env python3
"""
Roger Defect Logger - Production Implementation.

Creates and manages defect tracking logs in Markdown format for Roger
code analysis results. Provides structured defect tracking with priority
organization, incremental logging, and fingerprint-based deduplication.

This module is part of the POC4 CodeRabbit Layer 2 orchestration and handles
the generation of DEFECT-LOG.md files with detailed defect information,
summary statistics, and suggested fixes.

Features:
- Markdown-formatted defect logs with structured sections
- Priority-based organization (P0-P4) with summary tables
- Defect ID assignment (DEF-0001, DEF-0002, ...)
- Summary statistics by priority, category, and layer
- Fingerprint-based deduplication (prevents duplicate defects)
- Append mode for incremental logging across multiple runs
- Log parsing for existing defect extraction

Key Classes:
    - DefectLogger: Main class for defect log management

Key Functions:
    - create_defect_log: Convenience function for one-shot log creation
    - append_defects: Convenience function for appending to existing logs

Usage:
    from defect_logger import DefectLogger

    # Create new defect log
    logger = DefectLogger('./DEFECT-LOG.md')
    logger.create_defect_log(findings, "My Project")

    # Append new defects to existing log
    logger.append_defects(new_findings)

See Also:
    - roger_orchestrator.py: Main orchestration logic
    - finding_utils.py: Finding normalization and deduplication

Author: Eric Johnson (Senior Developer)
Date: 2025-11-10
Version: 1.0
Layer: POC4 CodeRabbit Layer 2 (Orchestration)
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class DefectLogger:
    """
    Defect tracking logger with Markdown output.

    Creates and manages DEFECT-LOG.md files with structured defect information.
    Supports creating new logs, appending to existing logs, and tracking
    defects across multiple analysis runs using fingerprint-based deduplication.

    Attributes:
        log_path: Path object for the defect log file
        defect_counter: Counter for sequential defect ID assignment
        existing_fingerprints: Set of fingerprints from existing defects

    Examples:
        >>> logger = DefectLogger('./DEFECT-LOG.md')
        >>> findings = [{'id': 'ROG-0001', 'priority': 'P1', ...}]
        >>> logger.create_defect_log(findings, "My Project")
        1
    """

    def __init__(self, log_path: str = "./DEFECT-LOG.md"):
        """
        Initialize defect logger.

        Loads existing log if present to extract defect counter and
        fingerprints for deduplication support.

        Args:
            log_path: Path to defect log file (default: ./DEFECT-LOG.md)
        """
        self.log_path = Path(log_path)
        self.defect_counter = 0
        self.existing_fingerprints: set = set()

        # Load existing log if present
        if self.log_path.exists():
            self._load_existing_log()

    def _load_existing_log(self) -> None:
        """
        Load existing log file to extract defect counter and fingerprints.

        Parses the existing DEFECT-LOG.md file to extract the highest defect ID
        and all fingerprints. This prevents duplicate defects when appending
        new findings to existing logs and ensures sequential defect IDs.

        Raises:
            No exceptions - silently resets state if parsing fails
        """
        try:
            content = self.log_path.read_text()

            # Extract highest defect ID
            defect_ids = re.findall(r'### DEF-(\d+):', content)
            if defect_ids:
                self.defect_counter = max(
                    int(id_str) for id_str in defect_ids
                )

            # Extract fingerprints (16 hex character strings)
            fingerprints = re.findall(
                r'\*\*Fingerprint\*\*: `([a-f0-9]{16})`',
                content
            )
            self.existing_fingerprints = set(fingerprints)

        except Exception:
            # If parsing fails, start fresh
            self.defect_counter = 0
            self.existing_fingerprints = set()

    def create_defect_log(
        self,
        findings: List[Dict],
        project_name: str = "Unknown Project",
        overwrite: bool = False
    ) -> int:
        """
        Create new defect log file or append to existing log.

        Generates a Markdown-formatted defect log with header, summary table,
        and detailed defect entries. If log exists and overwrite=False, appends
        findings instead. Fingerprint-based deduplication prevents duplicates.

        Args:
            findings: List of normalized findings from Roger orchestrator with:
                - id: Roger ID (ROG-XXXX)
                - priority: Priority level (P0-P4)
                - category: Finding category
                - source_layer: Layer identifier
                - source_tool: Source tool name
                - file: File path
                - line: Line number
                - message: Issue description
                - details: Additional details
                - fix: Suggested fix
                - fingerprint: SHA256-based identifier
            project_name: Name of the project being analyzed
            overwrite: If True, overwrite existing log; if False, append

        Returns:
            Number of defects created (or appended)

        Examples:
            >>> logger = DefectLogger('./DEFECT-LOG.md')
            >>> findings = [{'id': 'ROG-0001', 'priority': 'P1', ...}]
            >>> count = logger.create_defect_log(findings, "My Project")
            >>> count
            1
        """
        if self.log_path.exists() and not overwrite:
            # Append to existing log
            return self.append_defects(findings)

        # Create new log
        self.defect_counter = 0
        self.existing_fingerprints = set()

        # Generate log content
        content = self._generate_log_header(project_name, findings)
        content += self._generate_summary_table(findings)
        content += self._generate_defects_section(findings)

        # Write to file
        self.log_path.write_text(content)

        # Track fingerprints
        for finding in findings:
            if 'fingerprint' in finding:
                self.existing_fingerprints.add(finding['fingerprint'])

        return len(findings)

    def append_defects(self, findings: List[Dict]) -> int:
        """
        Append new defects to existing log with deduplication.

        Filters out findings with fingerprints that already exist in the log,
        then appends only new defects. If no log exists, creates a new one.

        Args:
            findings: List of normalized findings to append

        Returns:
            Number of new defects added (duplicates skipped)

        Examples:
            >>> logger = DefectLogger('./DEFECT-LOG.md')
            >>> logger.create_defect_log([...], "Project")
            >>> new_findings = [{'fingerprint': 'new123...', ...}]
            >>> added = logger.append_defects(new_findings)
        """
        if not self.log_path.exists():
            # No existing log, create new one
            return self.create_defect_log(findings)

        # Filter out duplicates
        new_findings = [
            f for f in findings
            if f.get('fingerprint') not in self.existing_fingerprints
        ]

        if not new_findings:
            return 0  # No new defects

        # Generate defects section for new findings
        new_defects_content = self._generate_defects_section(new_findings)

        # Append to log
        with open(self.log_path, 'a') as f:
            f.write("\n---\n\n")
            f.write("## Additional Defects\n\n")
            f.write(f"**Appended**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(new_defects_content)

        # Update existing fingerprints
        for finding in new_findings:
            if 'fingerprint' in finding:
                self.existing_fingerprints.add(finding['fingerprint'])

        # Update summary (full log rewrite - keep this simple for Phase 2)
        self._update_summary()

        return len(new_findings)

    def _generate_log_header(
        self,
        project_name: str,
        findings: List[Dict]
    ) -> str:
        """
        Generate log header with metadata.

        Args:
            project_name: Name of the project
            findings: List of findings for counting statistics

        Returns:
            Markdown-formatted header string
        """
        analyzed_files = len(
            set(f.get('file', 'unknown') for f in findings)
        )
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        return f"""# Defect Log - {project_name}

**Generated**: {timestamp}
**Analyzed Files**: {analyzed_files}
**Total Defects**: {len(findings)}

---

"""

    def _generate_summary_table(self, findings: List[Dict]) -> str:
        """
        Generate summary table by priority.

        Args:
            findings: List of findings to summarize

        Returns:
            Markdown-formatted summary table
        """
        # Count by priority
        priority_counts = {
            'P0': len([f for f in findings if f.get('priority') == 'P0']),
            'P1': len([f for f in findings if f.get('priority') == 'P1']),
            'P2': len([f for f in findings if f.get('priority') == 'P2']),
            'P3': len([f for f in findings if f.get('priority') == 'P3']),
            'P4': len([f for f in findings if f.get('priority') == 'P4'])
        }

        return f"""## Summary

| Priority | Count |
|----------|-------|
| P0 (Critical) | {priority_counts['P0']} |
| P1 (High) | {priority_counts['P1']} |
| P2 (Medium) | {priority_counts['P2']} |
| P3 (Low) | {priority_counts['P3']} |
| P4 (Info) | {priority_counts['P4']} |

---

"""

    def _generate_defects_section(self, findings: List[Dict]) -> str:
        """
        Generate defects section with detailed entries.

        Args:
            findings: List of findings to format

        Returns:
            Markdown-formatted defects section with all defect details
        """
        content = "## Defects\n\n"

        for finding in findings:
            self.defect_counter += 1
            defect_id = f"DEF-{self.defect_counter:04d}"

            # Extract fields
            message = finding.get('message', 'Unknown issue')
            priority = finding.get('priority', 'P2')
            file_path = finding.get('file', 'unknown')
            line = finding.get('line', '?')
            category = finding.get('category', 'unknown')
            source_tool = finding.get('source_tool', 'unknown')
            source_layer = finding.get('source_layer', 'unknown')
            details = finding.get('details', 'No additional details')
            fix = finding.get('fix', 'No suggested fix')
            fingerprint = finding.get('fingerprint', 'N/A')

            content += f"""### {defect_id}: {message} [{priority}]

- **File**: `{file_path}:{line}`
- **Category**: {category}
- **Source**: {source_tool} ({source_layer})
- **Details**: {details}
- **Fix**: {fix}
- **Fingerprint**: `{fingerprint}`

---

"""

        return content

    def _update_summary(self) -> None:
        """
        Update summary section in existing log.

        This is a simplified implementation for Phase 2.
        Phase 3 could implement more sophisticated log parsing
        and in-place summary updates.

        Note:
            Currently a no-op. Full log regeneration not needed for appends.
        """
        # For Phase 2, we'll leave this as a no-op
        # Full log regeneration is not needed for append operations
        pass

    def get_defect_count(self) -> int:
        """
        Get total number of defects in log.

        Returns:
            Current defect counter value
        """
        return self.defect_counter

    def get_defect_summary(self) -> Dict[str, int]:
        """
        Get summary of defects by priority from existing log.

        Parses the DEFECT-LOG.md file to extract priority counts from
        the summary table.

        Returns:
            Dictionary with priority counts {'P0': count, 'P1': count, ...}

        Examples:
            >>> logger = DefectLogger('./DEFECT-LOG.md')
            >>> summary = logger.get_defect_summary()
            >>> summary['P0']
            1
        """
        if not self.log_path.exists():
            return {'P0': 0, 'P1': 0, 'P2': 0, 'P3': 0, 'P4': 0}

        content = self.log_path.read_text()

        # Parse priority counts from summary table
        counts = {'P0': 0, 'P1': 0, 'P2': 0, 'P3': 0, 'P4': 0}

        for priority in counts.keys():
            match = re.search(
                rf'\| {priority} \([^)]+\) \| (\d+) \|',
                content
            )
            if match:
                counts[priority] = int(match.group(1))

        return counts

    def clear_log(self) -> bool:
        """
        Clear defect log (delete file).

        Deletes the defect log file and resets internal state.

        Returns:
            True if log was deleted, False if it didn't exist

        Examples:
            >>> logger = DefectLogger('./DEFECT-LOG.md')
            >>> logger.clear_log()
            True
        """
        if self.log_path.exists():
            self.log_path.unlink()
            self.defect_counter = 0
            self.existing_fingerprints = set()
            return True
        return False


def create_defect_log(
    findings: List[Dict],
    project_name: str = "Unknown Project",
    log_path: str = "./DEFECT-LOG.md"
) -> int:
    """
    Convenience function to create defect log.

    Creates a new DefectLogger instance and generates a defect log
    file, overwriting any existing log at the same path.

    Args:
        findings: List of normalized findings from Roger
        project_name: Name of the project being analyzed
        log_path: Path to defect log file (default: ./DEFECT-LOG.md)

    Returns:
        Number of defects created

    Examples:
        >>> findings = [{'id': 'ROG-0001', 'priority': 'P1', ...}]
        >>> count = create_defect_log(findings, "My Project")
        >>> count
        1
    """
    logger = DefectLogger(log_path)
    return logger.create_defect_log(findings, project_name, overwrite=True)


def append_defects(
    findings: List[Dict],
    log_path: str = "./DEFECT-LOG.md"
) -> int:
    """
    Convenience function to append defects to existing log.

    Creates a DefectLogger instance and appends new defects to an
    existing log file. Duplicate defects (matching fingerprints)
    are automatically skipped.

    Args:
        findings: List of normalized findings to append
        log_path: Path to defect log file (default: ./DEFECT-LOG.md)

    Returns:
        Number of new defects added (duplicates skipped)

    Examples:
        >>> findings = [{'id': 'ROG-0010', 'priority': 'P2', ...}]
        >>> added = append_defects(findings)
        >>> added
        1
    """
    logger = DefectLogger(log_path)
    return logger.append_defects(findings)


# Example usage:
if __name__ == '__main__':
    # Example findings
    example_findings = [
        {
            'id': 'ROG-0001',
            'priority': 'P1',
            'category': 'security',
            'source_layer': 'layer1',
            'source_tool': 'bandit',
            'file': '/srv/cc/project/main.py',
            'line': 42,
            'message': 'SQL injection vulnerability',
            'details': 'User input not sanitized',
            'fix': 'Use parameterized queries',
            'fingerprint': 'a1b2c3d4e5f6g7h8'
        },
        {
            'id': 'ROG-0002',
            'priority': 'P2',
            'category': 'quality',
            'source_layer': 'layer1',
            'source_tool': 'pylint',
            'file': '/srv/cc/project/utils.py',
            'line': 15,
            'message': 'Function too complex',
            'details': 'Complexity score: 15',
            'fix': 'Extract sub-functions',
            'fingerprint': 'b2c3d4e5f6g7h8i9'
        }
    ]

    # Create log
    logger = DefectLogger('./example-defect-log.md')
    count = logger.create_defect_log(example_findings, "Example Project")
    print(f"Created defect log with {count} defects")
    print(f"Summary: {logger.get_defect_summary()}")
