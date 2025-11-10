#!/usr/bin/env python3
"""
Roger Finding Utilities - Production Implementation.

Provides deduplication and normalization utilities for findings from
Layer 1 (linter aggregator) and Layer 3 (CodeRabbit).

This module is part of the POC4 CodeRabbit Layer 2 orchestration and provides
the core finding processing logic for Roger. It handles deduplication using
fingerprint-based matching, normalizes findings to a unified format, and
generates summary statistics for reporting.

Features:
- Fingerprint-based deduplication using SHA256 hashing
- Layer 1 precedence (Layer 1 findings take priority over Layer 3)
- Category equivalence mapping for consistent categorization
- Output normalization to unified Roger format
- Complementary finding detection (same location, different categories)
- Summary statistics generation

Key Functions:
    - deduplicate_findings: Remove duplicate findings across layers
    - normalize_findings: Convert findings to unified Roger format
    - generate_summary: Generate statistical summary of findings
    - generate_fingerprint: Create unique identifiers for findings

Usage:
    from finding_utils import (
        deduplicate_findings,
        normalize_findings,
        generate_summary
    )

    # Deduplicate Layer 1 and Layer 3 findings
    deduplicated = deduplicate_findings(layer1_findings, layer3_findings)

    # Normalize to Roger format with IDs
    normalized = normalize_findings(deduplicated)

    # Generate summary statistics
    summary = generate_summary(normalized)

See Also:
    - roger_orchestrator.py: Main orchestration logic
    - defect_logger.py: Defect log generation

Author: Eric Johnson (Senior Developer)
Date: 2025-11-10
Version: 1.0
Layer: POC4 CodeRabbit Layer 2 (Orchestration)
"""

import hashlib
from typing import Dict, List, Set, Tuple


# Category equivalence mapping (for deduplication)
CATEGORY_EQUIVALENCE = {
    "vulnerability": "security",
    "code_smell": "quality",
    "type_issue": "type_error",
    "cognitive_load": "complexity",
    "style": "formatting",
}


def normalize_category(category: str) -> str:
    """
    Normalize category name using equivalence mapping.

    Maps equivalent category names to their canonical forms for consistent
    deduplication and reporting. For example, 'vulnerability' maps to
    'security' and 'code_smell' maps to 'quality'.

    Args:
        category: Raw category name from linter or CodeRabbit

    Returns:
        Normalized category name (canonical form)

    Examples:
        >>> normalize_category('vulnerability')
        'security'
        >>> normalize_category('code_smell')
        'quality'
        >>> normalize_category('security')
        'security'
    """
    return CATEGORY_EQUIVALENCE.get(category, category)


def generate_fingerprint(file: str, line: int, category: str) -> str:
    """
    Generate unique fingerprint for finding deduplication.

    Creates a SHA256-based fingerprint from file path, line number, and
    category. The fingerprint is used to identify duplicate findings across
    Layer 1 and Layer 3. The category is normalized before hashing to ensure
    equivalent categories produce the same fingerprint.

    Fingerprint = SHA256(file + line + normalized_category)[:16]

    Args:
        file: File path (absolute or relative)
        line: Line number (use 0 if None or file-level finding)
        category: Finding category (will be normalized)

    Returns:
        16-character hexadecimal fingerprint string

    Examples:
        >>> generate_fingerprint('/srv/cc/test.py', 42, 'security')
        'a1b2c3d4e5f6a7b8'
        >>> generate_fingerprint('/srv/cc/test.py', 42, 'vulnerability')
        'a1b2c3d4e5f6a7b8'  # Same as 'security' (normalized)
    """
    normalized_category = normalize_category(category)
    key = f"{file}:{line or 0}:{normalized_category}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def deduplicate_findings(
    layer1_findings: List[Dict], layer3_findings: List[Dict]
) -> List[Dict]:
    """
    Deduplicate findings from Layer 1 and Layer 3 using precedence rules.

    Implements intelligent deduplication that preserves Layer 1 findings
    while allowing complementary Layer 3 insights. Unique Layer 3 categories
    (SOLID violations, design patterns, architecture) are never deduplicated.

    Deduplication Rules:
    1. Layer 1 precedence: Same file + line + category → keep Layer 1 only
    2. Unique Layer 3 categories: Never deduplicated (SOLID, design, arch)
    3. Complementary findings: Same file + line, different categories → keep
    4. Fingerprint-based matching: Uses SHA256 fingerprints for comparison

    Args:
        layer1_findings: Findings from linter aggregator (bandit, pylint, etc)
        layer3_findings: Findings from CodeRabbit AI enhancement

    Returns:
        Deduplicated list of findings (Layer 1 + unique Layer 3)

    Examples:
        >>> layer1 = [{'file': 'test.py', 'line': 42, 'category': 'security'}]
        >>> layer3 = [{'file': 'test.py', 'line': 42, 'category': 'security'}]
        >>> deduplicate_findings(layer1, layer3)
        [{'file': 'test.py', 'line': 42, 'category': 'security'}]
    """
    # Track seen fingerprints from Layer 1
    layer1_fingerprints: Set[str] = set()
    location_categories: Dict[Tuple[str, int], Set[str]] = {}

    # Process Layer 1 findings first (they have precedence)
    for finding_item in layer1_findings:
        file = finding_item.get("file", "unknown")
        line = finding_item.get("line", 0)
        category = normalize_category(finding_item.get("category", "unknown"))

        # Generate fingerprint
        fingerprint = generate_fingerprint(file, line, category)
        layer1_fingerprints.add(fingerprint)

        # Track location+category combinations
        location = (file, line)
        if location not in location_categories:
            location_categories[location] = set()
        location_categories[location].add(category)

    # Filter Layer 3 findings
    deduplicated_layer3 = []

    for layer3_finding in layer3_findings:
        file = layer3_finding.get("file", "unknown")
        line = layer3_finding.get("line", 0)
        category = normalize_category(layer3_finding.get("category", "unknown"))

        # Generate fingerprint
        fingerprint = generate_fingerprint(file, line, category)

        # Check if Layer 1 already reported this exact finding
        if fingerprint in layer1_fingerprints:
            continue  # Duplicate - Layer 1 takes precedence

        # Check if this is a unique Layer 3 category (never deduplicated)
        if category in ["solid_violation", "design_pattern", "architecture"]:
            deduplicated_layer3.append(layer3_finding)
            continue

        # Check if this is a complementary finding (same location, different category)
        location = (file, line)
        if location in location_categories:
            if category not in location_categories[location]:
                # Different category at same location - keep it (complementary)
                deduplicated_layer3.append(layer3_finding)
                location_categories[location].add(category)
        else:
            # New location - keep it
            deduplicated_layer3.append(layer3_finding)
            location_categories[location] = {category}

    # Combine Layer 1 + deduplicated Layer 3
    return layer1_findings + deduplicated_layer3


def normalize_finding(raw_finding: Dict, finding_id: str) -> Dict:
    """
    Normalize finding to unified Roger format.

    Converts raw findings from Layer 1 (linters) or Layer 3 (CodeRabbit)
    to a standardized format with consistent fields, normalized categories,
    and assigned Roger IDs for tracking.

    Args:
        finding: Raw finding from Layer 1 or Layer 3 with fields:
            - priority: Priority level (P0-P4)
            - category: Finding category (will be normalized)
            - source: Source tool (bandit, pylint, coderabbit, etc)
            - file: File path
            - line: Line number (optional)
            - message: Issue description
            - details: Additional details (optional)
            - fix: Suggested fix (optional)
        finding_id: Unique Roger ID (ROG-0001, ROG-0002, ...)

    Returns:
        Normalized finding dictionary in Roger format with fields:
            - id: Roger ID
            - priority: Priority level
            - category: Normalized category
            - source_layer: Layer identifier (layer1 or layer3)
            - source_tool: Source tool name
            - file: File path
            - line: Line number (None if file-level)
            - message: Issue description
            - details: Additional details
            - fix: Suggested fix (None if not provided)
            - fingerprint: SHA256-based unique identifier

    Examples:
        >>> finding = {'priority': 'P1', 'category': 'vulnerability',
        ...            'source': 'bandit', 'file': 'test.py', 'line': 42,
        ...            'message': 'SQL injection', 'details': 'Unsanitized',
        ...            'fix': 'Use parameterized queries'}
        >>> normalize_finding(finding, 'ROG-0001')
        {'id': 'ROG-0001', 'priority': 'P1', 'category': 'security', ...}
    """
    # Extract or infer fields from raw finding
    priority = raw_finding.get("priority", "P2")
    category = normalize_category(raw_finding.get("category", "unknown"))
    source_layer = raw_finding.get("source_layer", raw_finding.get("source", "unknown"))

    # Map Layer 1 source names to Layer 1 if not explicitly set
    layer1_tools = ["bandit", "pylint", "mypy", "radon", "black", "pytest"]
    if source_layer in layer1_tools:
        source_layer_normalized = "layer1"
        source_tool = source_layer
    elif source_layer == "coderabbit":
        source_layer_normalized = "layer3"
        source_tool = "coderabbit"
    else:
        source_layer_normalized = source_layer
        source_tool = raw_finding.get(
            "source_tool", raw_finding.get("source", "unknown")
        )

    file = raw_finding.get("file", "unknown")
    line = raw_finding.get("line", None)
    message = raw_finding.get("message", "Unknown issue")
    details = raw_finding.get("details", "No additional details")
    fix = raw_finding.get("fix", None)

    # Generate fingerprint if not present
    if "fingerprint" in raw_finding:
        fingerprint = raw_finding["fingerprint"]
    else:
        fingerprint = generate_fingerprint(file, line or 0, category)

    return {
        "id": finding_id,
        "priority": priority,
        "category": category,
        "source_layer": source_layer_normalized,
        "source_tool": source_tool,
        "file": file,
        "line": line,
        "message": message,
        "details": details,
        "fix": fix,
        "fingerprint": fingerprint,
    }


def normalize_findings(raw_findings: List[Dict]) -> List[Dict]:
    """
    Normalize list of findings to unified Roger format with ID assignment.

    Processes a list of raw findings (from Layer 1 or Layer 3) and converts
    each to the standardized Roger format with sequential ID assignment
    starting from ROG-0001.

    Args:
        raw_findings: List of raw findings from Layer 1 or Layer 3

    Returns:
        List of normalized findings with assigned Roger IDs (ROG-0001, ...)

    Examples:
        >>> findings = [
        ...     {'priority': 'P1', 'category': 'security', 'source': 'bandit',
        ...      'file': 'test.py', 'message': 'Issue 1'},
        ...     {'priority': 'P2', 'category': 'quality', 'source': 'pylint',
        ...      'file': 'test.py', 'message': 'Issue 2'}
        ... ]
        >>> normalized = normalize_findings(findings)
        >>> normalized[0]['id']
        'ROG-0001'
        >>> normalized[1]['id']
        'ROG-0002'
    """
    normalized_list = []
    for idx, raw_finding in enumerate(raw_findings, start=1):
        roger_id = f"ROG-{idx:04d}"
        normalized_list.append(normalize_finding(raw_finding, roger_id))
    return normalized_list


def _count_by_priority(findings: List[Dict]) -> Dict[str, int]:
    """
    Count findings by priority level (P0-P4).

    Args:
        findings: List of normalized findings

    Returns:
        Dictionary mapping priority levels to counts

    Examples:
        >>> findings = [{'priority': 'P1'}, {'priority': 'P1'}, {'priority': 'P2'}]
        >>> _count_by_priority(findings)
        {'P0': 0, 'P1': 2, 'P2': 1, 'P3': 0, 'P4': 0}
    """
    return {
        "P0": len([f for f in findings if f.get("priority") == "P0"]),
        "P1": len([f for f in findings if f.get("priority") == "P1"]),
        "P2": len([f for f in findings if f.get("priority") == "P2"]),
        "P3": len([f for f in findings if f.get("priority") == "P3"]),
        "P4": len([f for f in findings if f.get("priority") == "P4"]),
    }


def _count_by_category(findings: List[Dict]) -> Dict[str, int]:
    """
    Count findings by category (security, quality, etc).

    Args:
        findings: List of normalized findings

    Returns:
        Dictionary mapping categories to counts

    Examples:
        >>> findings = [{'category': 'security'}, {'category': 'quality'}]
        >>> _count_by_category(findings)
        {'security': 1, 'quality': 1}
    """
    category_counts = {}
    for item in findings:
        item_category = item.get("category", "unknown")
        category_counts[item_category] = category_counts.get(item_category, 0) + 1
    return category_counts


def _count_by_layer(findings: List[Dict]) -> Dict[str, int]:
    """
    Count findings by layer (layer1, layer3).

    Args:
        findings: List of normalized findings

    Returns:
        Dictionary mapping layers to counts

    Examples:
        >>> findings = [{'source_layer': 'layer1'}, {'source_layer': 'layer3'}]
        >>> _count_by_layer(findings)
        {'layer1': 1, 'layer3': 1}
    """
    return {
        "layer1": len([f for f in findings if f.get("source_layer") == "layer1"]),
        "layer3": len([f for f in findings if f.get("source_layer") == "layer3"]),
    }


def _generate_summary_text(total: int, priority_counts: Dict[str, int]) -> str:
    """
    Generate human-readable summary text.

    Args:
        total: Total number of findings
        priority_counts: Dictionary of counts by priority

    Returns:
        Human-readable summary string

    Examples:
        >>> _generate_summary_text(3, {'P0': 1, 'P1': 2, 'P2': 0, 'P3': 0, 'P4': 0})
        'Found 3 issues: 1 critical (P0), 2 high (P1)'
    """
    summary_text = f"Found {total} issue{'s' if total != 1 else ''}"

    priority_parts = []
    if priority_counts["P0"] > 0:
        priority_parts.append(f"{priority_counts['P0']} critical (P0)")
    if priority_counts["P1"] > 0:
        priority_parts.append(f"{priority_counts['P1']} high (P1)")
    if priority_counts["P2"] > 0:
        priority_parts.append(f"{priority_counts['P2']} medium (P2)")
    if priority_counts["P3"] > 0:
        priority_parts.append(f"{priority_counts['P3']} low (P3)")
    if priority_counts["P4"] > 0:
        priority_parts.append(f"{priority_counts['P4']} info (P4)")

    if priority_parts:
        summary_text += ": " + ", ".join(priority_parts)

    return summary_text


def generate_summary(findings: List[Dict]) -> Dict:
    """
    Generate comprehensive summary statistics from findings.

    Analyzes findings to produce counts by priority, category, and layer
    for reporting and visualization purposes.

    Args:
        findings: List of normalized finding dictionaries from Roger

    Returns:
        Dictionary with summary statistics including:
          - total_issues: Total number of findings
          - by_priority: Count breakdown by P0-P4 priority levels
          - by_category: Count breakdown by finding category
          - by_layer: Count breakdown by layer (layer1, layer3)
          - summary_text: Human-readable summary string

    Examples:
        >>> findings = [{'priority': 'P1', 'category': 'security', 'source_layer': 'layer1'}]
        >>> summary = generate_summary(findings)
        >>> summary['total_issues']
        1
        >>> summary['by_priority']['P1']
        1
    """
    total = len(findings)
    priority_counts = _count_by_priority(findings)
    category_counts = _count_by_category(findings)
    layer_counts = _count_by_layer(findings)
    summary_text = _generate_summary_text(total, priority_counts)

    return {
        "total_issues": total,
        "by_priority": priority_counts,
        "by_category": category_counts,
        "by_layer": layer_counts,
        "summary_text": summary_text,
    }


# Example usage
if __name__ == "__main__":
    # Example Layer 1 findings
    layer1 = [
        {
            "priority": "P1",
            "category": "security",
            "source": "bandit",
            "file": "/srv/cc/project/main.py",
            "line": 42,
            "message": "SQL injection vulnerability",
            "details": "User input not sanitized",
            "fix": "Use parameterized queries",
        },
        {
            "priority": "P2",
            "category": "quality",
            "source": "pylint",
            "file": "/srv/cc/project/utils.py",
            "line": 15,
            "message": "Unused variable",
            "details": 'Variable "foo" is defined but never used',
            "fix": "Remove unused variable",
        },
    ]

    # Example Layer 3 findings
    layer3 = [
        {
            "priority": "P1",
            "category": "security",  # Duplicate with Layer 1
            "source": "coderabbit",
            "source_layer": "layer3",
            "file": "/srv/cc/project/main.py",
            "line": 42,
            "message": "SQL injection detected",
            "details": "Raw SQL with user input",
        },
        {
            "priority": "P2",
            "category": "solid_violation",  # Unique Layer 3 category
            "source": "coderabbit",
            "source_layer": "layer3",
            "file": "/srv/cc/project/main.py",
            "line": 42,
            "message": "Single Responsibility Principle violation",
            "details": "Function does too many things",
        },
    ]

    # Deduplicate
    deduplicated = deduplicate_findings(layer1, layer3)
    print(f"Layer 1: {len(layer1)} findings")
    print(f"Layer 3: {len(layer3)} findings")
    print(f"Deduplicated: {len(deduplicated)} findings")
    print()

    # Normalize
    normalized = normalize_findings(deduplicated)
    print("Normalized findings:")
    for finding in normalized:
        print(
            f"  {finding['id']}: {finding['message']} "
            f"[{finding['priority']}] ({finding['source_layer']})"
        )
    print()

    # Summary
    summary = generate_summary(normalized)
    print(f"Summary: {summary['summary_text']}")
    print(f"By priority: {summary['by_priority']}")
    print(f"By category: {summary['by_category']}")
    print(f"By layer: {summary['by_layer']}")
