"""Optional framework and server integration surfaces."""

from .asgi import (
    AEP_PRINCIPAL_SCOPE_KEY,
    DEFAULT_INSPECT_CACHE_CONTROL,
    DEFAULT_MAXIMUM_REQUEST_BODY_BYTES,
    AepAsgiApplication,
    AepAuthenticationMiddleware,
    AsgiApplication,
    AsgiMessage,
    AsgiReceive,
    AsgiScope,
    AsgiSend,
    principal_from_scope,
)

__all__ = [
    "AEP_PRINCIPAL_SCOPE_KEY",
    "DEFAULT_INSPECT_CACHE_CONTROL",
    "DEFAULT_MAXIMUM_REQUEST_BODY_BYTES",
    "AepAsgiApplication",
    "AepAuthenticationMiddleware",
    "AsgiApplication",
    "AsgiMessage",
    "AsgiReceive",
    "AsgiScope",
    "AsgiSend",
    "principal_from_scope",
]
