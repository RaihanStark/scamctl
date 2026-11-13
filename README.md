# scamctl

> AI-Powered Scam, Phishing, & Malicious Attachment Detection CLI

`scamctl` is a high-performance command-line security tool written in **Go**. It protects freelancers, developers, and everyday users from sophisticated social engineering scams, infostealers, phishing campaigns, and trojanized attachments.

---

## Key Capabilities

### 1. Static File Forensics (Zero-Execution Sandbox Inspection)
- **True File Type Identification**: Sniffs magic bytes to catch disguised executables (e.g. Windows PE binaries disguised as `.pdf` or `.png`).
- **Deceptive Extension Analysis**: Detects double extensions (`invoice.pdf.exe`) and Unicode Right-To-Left Override (RLO `\u202E`) character tricks.
- **Deep Archive Inspection**: Scans inside `.zip`, `.tar`, and `.tar.gz` for hidden executable payloads, password-protected traps, and Zip Slip directory traversal attacks without extracting them to disk.
- **Office Document Security**: Detects hidden VBA macros (`vbaProject.bin`) and Remote Template Injection exploits (`TargetMode="External"`).
- **PDF Exploit Analysis**: Flags dangerous PDF object dictionary triggers (`/Launch`, `/JavaScript`, `/OpenAction`, `/EmbeddedFiles`).
- **Windows LNK Shortcut Inspection**: Parses `.lnk` files for stealthy PowerShell, CMD, curl, or mshta downloaders.

### 2. AI Semantic & Intent Analysis
- Powered out-of-the-box by **Google Antigravity (`agy`)** CLI (no external API keys required).
- Evaluates psychological triggers: artificial urgency, panic coercion, authority impersonation (PayPal, Geek Squad, HR, Banks).
- Detects off-platform communication traps (Telegram, WhatsApp, Signal).
- Catches financial advance-fee and fake check schemes ("buy equipment from our vendor").
- Correlates message claims with file realities (e.g., job says "view design mockups", but the archive holds a PowerShell stager).

---

## Installation & Build

```bash
# Clone the repository
cd scamctl

# Build the binary
go build -o scamctl main.go

# Optional: Install to system PATH
sudo mv scamctl /usr/local/bin/
```

---

## Usage

### 1. Scan a Suspicious Attachment
```bash
scamctl scan ./Suspicious_Brief.pdf.zip
```
*Tip: Add `--no-ai` to run purely static forensics offline at lightning speed.*

### 2. Check a Suspicious Message / Email
```bash
# Direct argument:
scamctl check "Please contact hiring on Telegram @recruiter to receive your equipment check."

# Or analyze a saved email / message file:
scamctl check -f suspicious_email.eml

# Or pipe from stdin:
cat proposal.txt | scamctl check
```

### 3. Correlated Triage (File + Message)
```bash
scamctl triage -f contract.pdf -m "Please sign this contract and run the verification utility."
```

### 4. Machine-Readable JSON Output
```bash
scamctl scan ./test.zip --json
```

---

## ⚠️ Disclaimer & Security Notice

> **IMPORTANT: `scamctl` is designed solely as an early-warning detection, triage, and educational reference tool. It is NOT a substitute for comprehensive endpoint security or professional human judgment.**

Please read and understand the following considerations:

1. **Not a Sole Line of Defense:**
   * Never rely on `scamctl` as your only security protection.
   * Always maintain an up-to-date operating system, active Endpoint Detection & Response (EDR) or Antivirus (AV) solution, and proper browser protections.

2. **No Guarantee of Zero False Negatives:**
   * Novel threats, zero-day exploits, bespoke social engineering lures, and polymorphic cryptors can evade automated heuristics and AI analysis.
   * A **`[SAFE]`** verdict indicates only that no known red flags or suspicious indicators were identified during the scan—it does **not** guarantee that a file or communication is 100% benign.

3. **Human Discretion & Best Practices:**
   * If a client, employer, or sender asks you to bypass platform rules, download unexpected archives, or run external commands, treat it with suspicion regardless of scan results.
   * If you are in doubt about an unknown file, inspect it inside an isolated virtual machine or sandbox, or discard it immediately.

4. **Limitation of Liability:**
   * This software is provided "as is", without warranty of any kind, express or implied. The developers and contributors assume no liability for any security breaches, malware infections, financial losses, data loss, or damages arising from the use of or reliance on this tool.

---

## License
MIT
