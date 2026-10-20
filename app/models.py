from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = list(Severity)
SCORE_PENALTY = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    description: str  # what we found
    impact: str  # why it matters
    fix: str  # what to do, in plain language
    evidence: str = ""
    snippets: dict[str, str] = field(default_factory=dict)  # platform -> copy-paste fix
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def ok(self, message: str) -> None:
        self.passed.append(message)


def grade_for(score: int) -> str:
    for threshold, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= threshold:
            return grade
    return "F"


def max_severity(severities: list[Severity]) -> Severity:
    return min(severities, key=SEVERITY_ORDER.index)


def summarize(report: Report, **meta) -> dict:
    findings = sorted(report.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
    counts = {s.value: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity.value] += 1
    score = max(0, 100 - sum(SCORE_PENALTY[f.severity] for f in findings))
    return {
        **meta,
        "score": score,
        "grade": grade_for(score),
        "summary": counts,
        "findings": [f.to_dict() for f in findings],
        "passed": report.passed,
    }
