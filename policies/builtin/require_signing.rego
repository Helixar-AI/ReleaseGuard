package releaseguard.builtin.require_signing

# Deny if signing is required by policy but no signature is present
deny["artifact must be signed"] {
    input.policy.signing.enabled == true
    not input.signed
}
