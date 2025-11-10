# Defect Log - Unknown Project

**Generated**: 2025-11-10 22:55:45
**Analyzed Files**: 1
**Total Defects**: 3

---

## Summary

| Priority | Count |
|----------|-------|
| P0 (Critical) | 0 |
| P1 (High) | 0 |
| P2 (Medium) | 3 |
| P3 (Low) | 0 |
| P4 (Info) | 0 |

---

## Defects

### DEF-0001: Similar lines in 2 files
==defect_logger:[487:493]
==test_roger:[286:292]
            {
                "id": "ROG-0001",
                "priority": "P1",
                "category": "security",
                "source_layer": "layer1",
                "source_tool": "bandit", [Priority.MEDIUM]

- **File**: `.claude/agents/roger/test_roger.py:1`
- **Category**: Category.QUALITY
- **Source**: pylint (layer1)
- **Details**: duplicate-code (R0801)
- **Fix**: None
- **Fingerprint**: `3c84746281f77d6c`

---

### DEF-0002: Similar lines in 2 files
==defect_logger:[500:506]
==test_roger:[339:345]
            {
                "id": "ROG-0002",
                "priority": "P2",
                "category": "quality",
                "source_layer": "layer1",
                "source_tool": "pylint", [Priority.MEDIUM]

- **File**: `.claude/agents/roger/test_roger.py:1`
- **Category**: Category.QUALITY
- **Source**: pylint (layer1)
- **Details**: duplicate-code (R0801)
- **Fix**: None
- **Fingerprint**: `7a014cc38c047df5`

---

### DEF-0003: Similar lines in 2 files
==defect_logger:[493:498]
==finding_utils:[474:479]
            "file": "/srv/cc/project/main.py",
            "line": 42,
            "message": "SQL injection vulnerability",
            "details": "User input not sanitized",
            "fix": "Use parameterized queries", [Priority.MEDIUM]

- **File**: `.claude/agents/roger/test_roger.py:1`
- **Category**: Category.QUALITY
- **Source**: pylint (layer1)
- **Details**: duplicate-code (R0801)
- **Fix**: None
- **Fingerprint**: `f1084bf71a6ccda0`

---

