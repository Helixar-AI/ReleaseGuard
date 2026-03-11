package releaseguard.builtin.no_sourcemaps

# Deny if any artifact path ends with .map
deny[artifact] {
    artifact := input.manifest.artifacts[_]
    endswith(artifact.path, ".map")
}
