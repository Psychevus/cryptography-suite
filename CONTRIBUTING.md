# Contributing

We welcome improvements to *cryptography-suite*. This guide outlines what we expect when submitting changes.

## Code of Conduct

Please adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) (placeholder).

## Branching and Pull Requests

- Branch from `main` and keep changes focused on a single topic.
- Open pull requests against `main`.
- Include a clear description, checklist of work, and reference relevant issues.
- Small, frequent pull requests are preferred over large ones.

## Reporting Issues

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) for defects and the [security report template](.github/ISSUE_TEMPLATE/security_report.md) for potential vulnerabilities.
For security disclosures, follow the process outlined in our [SECURITY policy](SECURITY.md).

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) such as `feat:`, `fix:`, `docs:`, `test:`, or `chore:`.

## Signed Commits

All commits **must be GPG-signed**.

```bash
# one-time setup
gpg --full-generate-key
git config --global user.signingkey <key-id>
git config --global commit.gpgsign true
```

Verify signatures with `git log --show-signature`.

## Testing Requirements

- Unit tests: `tox` or `pytest -q` must pass.
- Property-based tests: use [Hypothesis](https://hypothesis.readthedocs.io/) for new cryptographic logic.
- Coverage: maintain **≥95%** line coverage (`pytest --cov`).

## Security Considerations

Pull requests touching security-sensitive code **must include a `Threat Considerations` section** describing potential misuses and mitigations.

Thank you for helping make cryptography-suite safer.
