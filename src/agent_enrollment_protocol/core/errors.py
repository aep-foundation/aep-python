from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    path: str
    message: str


class AepError(Exception):
    """Base exception for AEP Core failures."""


class AepValidationError(AepError):
    def __init__(self, message: str, issues: tuple[ValidationIssue, ...]) -> None:
        super().__init__(message)
        self.issues = issues


class AepAuthorizationError(AepError):
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class AepAssertionError(AepError):
    pass


def validation_issues(error: Exception) -> tuple[ValidationIssue, ...]:
    errors = getattr(error, "errors", None)
    if not callable(errors):
        return (ValidationIssue(path="$", message=str(error)),)
    issues: list[ValidationIssue] = []
    for item in errors(include_url=False):
        location = item.get("loc", ())
        path = "$" + "".join(_path_segment(part) for part in location)
        issues.append(ValidationIssue(path=path, message=str(item.get("msg", "Invalid value."))))
    return tuple(issues)


def _path_segment(part: Any) -> str:
    if isinstance(part, int):
        return f"[{part}]"
    return f".{part}"
