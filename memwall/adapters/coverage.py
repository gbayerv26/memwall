"""Account for omissions within the selected adapter scope."""
from collections import Counter
from dataclasses import dataclass, field
import os


@dataclass
class Coverage:
    target: str
    format: str
    selected_sources: int = 0
    complete_sources: int = 0
    records: int = 0
    _opened_sources: int = 0
    issue_counts: Counter = field(default_factory=Counter)
    examples: list = field(default_factory=list)

    def issue(self, code, path, location=None):
        self.issue_counts[code] += 1
        if len(self.examples) >= 12:
            return
        # Keep examples bounded and avoid raw input, exception text and absolute paths.
        root = os.path.dirname(os.path.abspath(self.target)) if os.path.isfile(self.target) else self.target
        try:
            locator = os.path.relpath(path, root)
        except ValueError:  # Paths can be on different Windows drives.
            locator = os.path.basename(path)
        if locator == os.pardir or locator.startswith(os.pardir + os.sep):
            locator = os.path.basename(path)
        example = {"code": code, "source": ascii(locator)[:200]}
        if location is not None:
            example["location"] = location
        self.examples.append(example)

    @property
    def status(self):
        if self.issue_counts:
            return "partial" if self._opened_sources or self.records else "failed"
        return "complete" if self.selected_sources else "no_sources"

    @property
    def complete(self):
        return self.status == "complete"

    def summary(self):
        details = ", ".join(f"{code}={count}" for code, count in sorted(self.issue_counts.items()))
        message = f"coverage: {self.status} ({self.complete_sources}/{self.selected_sources} sources complete)"
        return f"{message}; {details}" if details else message

    def to_dict(self):
        return {
            "status": self.status,
            "format": self.format,
            "selected_sources": self.selected_sources,
            "complete_sources": self.complete_sources,
            "records": self.records,
            "issue_counts": dict(sorted(self.issue_counts.items())),
            "examples": self.examples,
        }
