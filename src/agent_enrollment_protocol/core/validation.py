from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, cast

from pydantic import BaseModel, TypeAdapter, ValidationError

from .errors import AepValidationError, ValidationIssue, validation_issues
from .models import PlatformSignResponse

ModelT = TypeVar("ModelT", bound=BaseModel)
ValueT = TypeVar("ValueT")


@dataclass(frozen=True, slots=True)
class ValidationResult(Generic[ValueT]):
    value: ValueT | None
    issues: tuple[ValidationIssue, ...]

    @property
    def ok(self) -> bool:
        return not self.issues


def parse_json_model(data: str | bytes, model: type[ModelT], document_type: str) -> ModelT:
    _reject_duplicate_members(data, document_type)
    try:
        return model.model_validate_json(data)
    except ValidationError as error:
        raise AepValidationError(
            f"Invalid AEP {document_type}.", validation_issues(error)
        ) from error


def validate_json_model(
    data: str | bytes, model: type[ModelT], document_type: str
) -> ValidationResult[ModelT]:
    try:
        return ValidationResult(value=parse_json_model(data, model, document_type), issues=())
    except AepValidationError as error:
        return ValidationResult(value=None, issues=error.issues)


def parse_platform_sign_response(data: str | bytes) -> PlatformSignResponse:
    return cast(
        PlatformSignResponse,
        _parse_json_value(data, PlatformSignResponse, "Platform Sign response"),
    )


def _parse_json_value(data: str | bytes, value_type: Any, document_type: str) -> Any:
    _reject_duplicate_members(data, document_type)
    try:
        return TypeAdapter(value_type).validate_json(data, strict=True)
    except ValidationError as error:
        raise AepValidationError(
            f"Invalid AEP {document_type}.", validation_issues(error)
        ) from error


def _reject_duplicate_members(data: str | bytes, document_type: str) -> None:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"duplicate object member: {key}")
            result[key] = value
        return result

    try:
        json.loads(data, object_pairs_hook=pairs)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
        raise AepValidationError(
            f"Invalid AEP {document_type} JSON.",
            (ValidationIssue(path="$", message=str(error)),),
        ) from error
