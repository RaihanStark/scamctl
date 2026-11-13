# AI Assistance & Creation Notice

This repository and its codebase were **heavily created and developed with AI assistance**, specifically utilizing **Google's Gemini model** via the **Antigravity** agent platform developed by Google DeepMind.

---

## Scope of AI Generation

AI was utilized in the development of:
* **Architecture & Design:** Project organization, command-line ergonomics, and dual-engine triage structure.
* **Core Codebase (Go):** Static file analysis engines (magic byte inspection, archive traversing, Office OpenXML relationships parsing, PDF stream scanner, LNK parser).
* **AI Provider Integration:** CLI sub-process integration bridging local Antigravity runtime sessions with structured JSON schema evaluation.
* **Testing & Documentation:** Unit test suites (`pkg/forensic/scanner_test.go`), threat taxonomy (`STATIC_THREATS.md`), and reference documentation.

---

## Transparency & Human Review

In the spirit of open-source transparency:
1. **Security Tool Auditing:** While the codebase includes automated unit test suites and static analysis checks, all AI-generated code should be reviewed, audited, and tested according to your organization's security standards before deployment in critical environments.
2. **Community Feedback:** Contributions, issues, and security reviews from human security researchers and Go developers are welcomed and encouraged.
