#!/usr/bin/env bash
# Print basic session information using only Bash builtins.
printf 'Host: %s\n' "${HOSTNAME:-unknown}"
printf 'User: %s (uid=%s)\n' "${USER:-unknown}" "$UID"
printf 'Bash: %s\n' "$BASH_VERSION"
printf 'Working directory: %s\n' "$PWD"
