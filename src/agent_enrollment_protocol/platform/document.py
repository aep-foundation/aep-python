from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlsplit

from agent_enrollment_protocol.core import (
    AEP_PLATFORM_WELL_KNOWN_PATH,
    AEP_VERSION,
    PlatformDiscoveryDocument,
    PlatformEndpoints,
    PlatformHttp,
    PlatformIdentityConfiguration,
    PlatformMetadata,
    PlatformSigningConfiguration,
    SigningAlgorithm,
)

from .types import DidVerificationMethod, DiscoveryOptions, IdentityRecord

DID_MEDIA_TYPE = "application/did+json"
HOSTED_IDENTITY_DRAFT = "draft-kavian-aep-platform-hosted-identity-01"
WELL_KNOWN_PATH = AEP_PLATFORM_WELL_KNOWN_PATH
_DID_CONTEXT = "https://www.w3.org/ns/did/v1"
_DID_PLACEHOLDER = "{agent_did_id}"


def create_service_scoped_agent_did(host: str, path_prefix: str, agent_did_id: str) -> str:
    parsed = urlsplit(f"https://{host}")
    if (
        not host
        or not agent_did_id
        or parsed.hostname is None
        or parsed.netloc != host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("AEP Platform DID host or Agent DID identifier is invalid")
    components = ["did", "web", _encode_did_component(host)]
    components.extend(
        _encode_did_component(part) for part in path_prefix.strip("/").split("/") if part
    )
    components.append(_encode_did_component(agent_did_id))
    return ":".join(components)


def create_did_document(identity: IdentityRecord, method: DidVerificationMethod) -> dict[str, Any]:
    if (
        method.id != identity.key_id
        or method.controller != identity.agent_did
        or not method.type
        or not method.public_key_jwk
    ):
        raise ValueError("AEP Platform DID verification method does not match the managed identity")
    return {
        "@context": [_DID_CONTEXT],
        "assertionMethod": [method.id],
        "authentication": [method.id],
        "capabilityInvocation": [method.id],
        "id": identity.agent_did,
        "verificationMethod": [
            {
                "controller": method.controller,
                "id": method.id,
                "publicKeyJwk": dict(method.public_key_jwk),
                "type": method.type,
            }
        ],
    }


def create_discovery_document(
    options: DiscoveryOptions,
    *,
    did_url_template: str,
    hosted_verification: bool,
    signing_algorithms: tuple[SigningAlgorithm, ...],
    default_lifetime_seconds: int,
) -> PlatformDiscoveryDocument:
    for name, path in (
        ("endpoint base", options.endpoint_base),
        ("lifecycle", options.lifecycle_endpoint),
        ("list", options.list_endpoint),
        ("provision", options.provision_endpoint),
        ("sign", options.sign_endpoint),
    ):
        _validate_endpoint_path(name, path)
    if hosted_verification != (options.hosted_verification_endpoint is not None):
        raise ValueError("AEP Platform hosted verification flag and endpoint must agree")
    if options.hosted_verification_endpoint is not None:
        _validate_endpoint_path("hosted verification", options.hosted_verification_endpoint)
    if not options.platform_name:
        raise ValueError("AEP Platform name is required")
    render_did_url(did_url_template, "validation")
    endpoints: dict[str, str] = {
        "lifecycle": options.lifecycle_endpoint,
        "list": options.list_endpoint,
        "provision": options.provision_endpoint,
        "sign": options.sign_endpoint,
    }
    if options.hosted_verification_endpoint is not None:
        endpoints["hosted_verification"] = options.hosted_verification_endpoint
    platform: dict[str, object] = {
        "hosted_verification": hosted_verification,
        "name": options.platform_name,
    }
    if options.platform_did is not None:
        platform["did"] = options.platform_did
    return PlatformDiscoveryDocument(
        aep_version=AEP_VERSION,
        endpoints=PlatformEndpoints.model_validate(endpoints),
        http=PlatformHttp(endpoint_base=options.endpoint_base),
        identity=PlatformIdentityConfiguration(
            did_methods=("did:web",), did_url_template=did_url_template
        ),
        platform=PlatformMetadata.model_validate(platform),
        signing=PlatformSigningConfiguration(
            algorithms=signing_algorithms,
            default_lifetime_seconds=str(default_lifetime_seconds),
        ),
    )


def render_did_url(template: str, agent_did_id: str) -> str:
    if template.count(_DID_PLACEHOLDER) != 1:
        raise ValueError(
            "AEP Platform DID URL template must contain one {agent_did_id} placeholder"
        )
    rendered = template.replace(_DID_PLACEHOLDER, _encode_did_component(agent_did_id))
    parsed = urlsplit(rendered)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("AEP Platform DID URL template must render an absolute HTTPS URL")
    return rendered


def _validate_endpoint_path(name: str, path: str) -> None:
    parsed = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"AEP Platform {name} endpoint must be an absolute path")


def _encode_did_component(value: str) -> str:
    return quote(value, safe="-._~!$&'()*+,;=")
