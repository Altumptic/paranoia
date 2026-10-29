# Security policy

Paranoia follows the [Altumptic vulnerability disclosure policy](https://altumptic.com/security). This page is the short version for this repository.

## Reporting a vulnerability

Please report privately — not in a public issue.

| | |
| --- | --- |
| Email | thefear078@gmail.com |
| PGP key | <https://altumptic.com/.well-known/pgp-key.txt> |
| Fingerprint | `117B A978 F332 80B5 12EE 84B5 D278 3C4F DE43 0CA6` (Ed25519 / Cv25519) |
| Machine-readable | <https://altumptic.com/.well-known/security.txt> |

Include the Paranoia version, the steps or the file that triggers the problem, the impact you see and how to reach you. Encrypt with the key above when the report contains exploit details. For a quick question before reporting, Telegram [@thefear078](https://t.me/thefear078) works — send details only by email.

## Scope

In scope: the **latest release** of Paranoia — the desktop app, the `paranoia-engine` sidecar, the `paranoia` CLI and the code in this repository.

Especially interesting:

- a crafted binary, PDB or `.pat` file that makes the engine crash, hang, read or write outside its buffers, or run code;
- a way for content shown in the app (names, strings, comments, pseudocode) to run script in the window or to reach the desktop bridge;
- a way around the native confirmations (debugger start, Python scripts) or the file allow-list described in [docs/SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md);
- a problem in the release verification chain ([docs/VERIFY.md](docs/VERIFY.md)).

Out of scope: denial of service by load, social engineering, third-party services (GitHub, Sigstore), scanner output without a working proof of concept, and the documented non-goals (for example: malware you start in the debugger runs on your machine — that is what a debugger does).

## What you can expect

As stated in the Altumptic policy:

- acknowledgement within **3 business days**;
- a first assessment and severity within **10 business days**;
- a fix or mitigation as fast as severity demands — normally within **90 days** — with updates along the way;
- public credit in the release notes if you want it.

Good-faith research within the policy is covered by the safe harbor described at <https://altumptic.com/security>.

## Supported versions

Only the latest release receives security fixes. Releases are published at <https://github.com/Altumptic/paranoia/releases>; [docs/VERIFY.md](docs/VERIFY.md) shows how to check that a download is genuine.
