from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .constants import AEP_CLAIM_NAMES
from .models import ClaimValues, InspectClaims


@dataclass(frozen=True, slots=True)
class ClaimSupportEvaluation:
    can_satisfy_required: bool
    supported_optional: tuple[str, ...]
    supported_preferred: tuple[str, ...]
    unsupported_required: tuple[str, ...]


def evaluate_claim_support(
    requested: InspectClaims | None, supported_claim_names: Sequence[str] = AEP_CLAIM_NAMES
) -> ClaimSupportEvaluation:
    supported = frozenset(supported_claim_names)
    required = requested.required or () if requested is not None else ()
    preferred = requested.preferred or () if requested is not None else ()
    optional = requested.optional or () if requested is not None else ()
    unsupported_required = tuple(name for name in required if name not in supported)
    return ClaimSupportEvaluation(
        can_satisfy_required=not unsupported_required,
        supported_optional=tuple(name for name in optional if name in supported),
        supported_preferred=tuple(name for name in preferred if name in supported),
        unsupported_required=unsupported_required,
    )


def missing_required_claim_names(
    required: Sequence[str], values: ClaimValues | None
) -> tuple[str, ...]:
    supplied = values.to_wire() if values is not None else {}
    return tuple(name for name in required if name not in supplied)
