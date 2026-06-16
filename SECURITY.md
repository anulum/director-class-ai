# Security Policy

Director-Class AI governs autonomous and mission-critical systems, so security
reports are handled with priority.

## Reporting a vulnerability

Email **protoscience@anulum.li** with "Director-Class AI security" in the subject.
Do not open public issues for vulnerabilities. Include a description, affected
version/commit, and reproduction steps. Acknowledgement within 72 hours.

## Scope of particular interest

- Bypass of the action-plane kill-switch (a destructive command that evades the
  detector via obfuscation, encoding, or alternate syntax).
- Fusion logic that allows an action it should have blocked (fail-closed bypass).
- Prompt-injection that reaches the effector through an untrusted-content path.
