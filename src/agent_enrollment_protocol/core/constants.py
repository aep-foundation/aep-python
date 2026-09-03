from typing import Final

AEP_VERSION: Final = "1.0"
AEP_MEDIA_TYPE: Final = "application/aep+json"
AEP_PROBLEM_MEDIA_TYPE: Final = "application/problem+json"
AEP_PLATFORM_WELL_KNOWN_PATH: Final = "/.well-known/aep-platform"
AEP_AUTH_SCHEME: Final = "AEP"
AEP_AUTHORIZATION_HEADER: Final = "AEP-Authorization"
AEP_WELL_KNOWN_PATH: Final = "/.well-known/aep"
DEFAULT_HTTP_ENDPOINT_BASE: Final = "/aep/"
MAX_ASSERTION_LIFETIME_SECONDS: Final = 300

AEP_COMMANDS: Final = ("inspect", "enroll", "grant", "revoke", "status")
AEP_AUTHENTICATED_COMMANDS: Final = ("enroll", "grant", "revoke", "status")
AEP_ASSERTION_OPERATIONS: Final = (*AEP_AUTHENTICATED_COMMANDS, "authenticate")
AEP_AUTHENTICATION_METHOD_JWT: Final = "aep-jwt"

AEP_BINDINGS: Final = ("http",)
AEP_SIGNING_ALGORITHMS: Final = ("EdDSA", "ES256")
AEP_IDENTITY_METHOD_DID_WEB: Final = "did:web"

AEP_CLAIM_NAME_CONTACT_ADDRESS_PRIMARY: Final = "contact.address.primary"
AEP_CLAIM_NAME_CONTACT_EMAIL: Final = "contact.email"
AEP_CLAIM_NAME_CONTACT_MOBILE: Final = "contact.mobile"
AEP_CLAIM_NAME_PERSON_BIRTHDATE: Final = "person.birthdate"
AEP_CLAIM_NAME_PERSON_FIRST_NAME: Final = "person.first_name"
AEP_CLAIM_NAME_PERSON_LAST_NAME: Final = "person.last_name"
AEP_CLAIM_NAME_PERSON_USERNAME: Final = "person.username"
AEP_CLAIM_NAMES: Final = (
    AEP_CLAIM_NAME_CONTACT_ADDRESS_PRIMARY,
    AEP_CLAIM_NAME_CONTACT_EMAIL,
    AEP_CLAIM_NAME_CONTACT_MOBILE,
    AEP_CLAIM_NAME_PERSON_BIRTHDATE,
    AEP_CLAIM_NAME_PERSON_FIRST_NAME,
    AEP_CLAIM_NAME_PERSON_LAST_NAME,
    AEP_CLAIM_NAME_PERSON_USERNAME,
)

AEP_GRANT_TYPE_OAUTH_BEARER: Final = "oauth-bearer"
AEP_GRANT_TYPE_API_KEY: Final = "api-key"
AEP_GRANT_TYPE_BASIC: Final = "basic"
AEP_BUILT_IN_GRANT_TYPES: Final = (
    AEP_GRANT_TYPE_OAUTH_BEARER,
    AEP_GRANT_TYPE_API_KEY,
    AEP_GRANT_TYPE_BASIC,
)
