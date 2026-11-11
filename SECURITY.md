# Security and deployment scope

SAVOP is intended for isolated research experiments on a dedicated Linux VM.
It is not a production router or an Internet-facing management service.

## 🔐 Lab boundaries

- Do not expose Agent control interfaces, test RPKI services or Docker sockets to untrusted networks
- Use synthetic lab addresses and fresh, explicitly selected evidence roots
- Review privileged commands before running network tests
- Replace example credentials in private per-run configurations; do not commit real credentials

## 💬 Reporting a problem

Do not include credentials or exploitable details in a public issue. Use GitHub
private vulnerability reporting if it is available for this repository. Otherwise,
request a private maintainer contact without publishing the sensitive details.
