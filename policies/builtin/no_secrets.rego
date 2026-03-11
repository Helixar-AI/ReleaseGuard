package releaseguard.builtin.no_secrets

# Deny if any finding has category "secret"
deny[finding] {
    finding := input.findings[_]
    finding.category == "secret"
}
