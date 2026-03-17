# Security Policy

## Supported Versions

Only the core AI orchestration framework (the "White Box" elements) is available for public observation.

| Version | Supported          |
| ------- | ------------------ |
| v4.1+   | :white_check_mark: |
| < v4.0  | :x:                |

## Reporting a Vulnerability

Please do not open a public issue to report security vulnerabilities. 
If you find a security vulnerability regarding our architecture or external API exposures, please report it privately.

## Implementation Disclaimer (Hybrid Black Box)

This repository serves as a **Hybrid Implementation**. 

While the architectural routing, workflow state-machines, and API structures are visible, the **Core "Secret Sauce" Data Moats** are deliberately decoupled and omitted from this public repository. 

Specifically, the following proprietary components are heavily restricted:
1. **The Acceptance Intelligence Graph:** The hierarchical confidence logic weights that power the Acceptance Graph are loaded dynamically from an untracked, encrypted configuration.
2. **Predictive Deduplication Salts:** Fingerprinting mechanisms utilize environment-specific salts not present in the code.
3. **Internal Tools:** Various internal report generation templates, raw findings ledgers (`*.jsonl`), and standalone scripts have been explicitly gitignored to protect intellectual property.

Attempting to run this system exactly as cloned will automatically fallback to "Demo Mode", utilizing highly generic (and largely ineffective) predictive weights.
