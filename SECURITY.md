# Security policy

dockhand-mcp's design and threat model are in [`docs/SECURITY.md`](docs/SECURITY.md). This file
is about reporting vulnerabilities in it.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub's private vulnerability
reporting: the repository's **Security** tab › **Report a vulnerability**, or directly at
<https://github.com/tyler-rich/dockhand-mcp/security/advisories/new>. Only the maintainers and you
can see the report. Include the version (or image digest), the profile, what an attacker
controls, and the steps or a proof of concept. Remove your own tokens and deployment details.

In scope: this server and its container image, for example a way to reach an excluded endpoint,
run a destructive tool without a human's approval, call a tool outside the configured profile,
bypass authentication or rate limits, make a secret appear in a tool result or a log line, or
write a compose file the guardrails should have refused. Vulnerabilities in DockHand itself belong
to DockHand's maintainers; vulnerabilities in a dependency, to its project (tell us too if it
affects dockhand-mcp).

## What happens next

- Acknowledgement within 7 days, and an assessment within 14.
- **Coordinated disclosure, 90 days:** we fix and release within 90 days of the report, and
  publish a GitHub security advisory with the fix, crediting you unless you prefer otherwise.
  If a fix needs longer, we agree a date with you; if the issue is actively exploited, we may
  publish sooner.
- Fixes ship in a new patch release; the published image is also rescanned weekly for
  vulnerabilities in its dependencies.

## Supported versions

Only the latest release receives fixes. Verify an image before you run it with the
`cosign verify` line in its release notes.
