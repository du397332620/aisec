# Third-party engines

AIsec invokes optional scanners as separate executables or services and does not
modify their licensing:

- Opengrep — LGPL-2.1
- Gitleaks — MIT
- Trivy — Apache-2.0
- MobSF — GPL-3.0 (never bundled; user-managed service only)
- OWASP ZAP — Apache-2.0 (future dynamic adapter; never downloaded at scan time)

Their names and licenses belong to their respective projects. A scanner result
records the exact executable version whenever it can be determined.

Runtime libraries distributed through npm:

- Ajv — MIT
- ajv-formats — MIT
- TypeScript — Apache-2.0
- yaml — ISC
