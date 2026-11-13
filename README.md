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

### 3. Reverse Engineer Malware (Understand How It Works)
```bash
# Deep dissection of binaries, executables, scripts, or archives
scamctl reverse ./suspicious_file.exe

# Or reverse engineer without AI (pure offline forensics):
scamctl reverse ./suspicious_file.exe --no-ai
```
- Dissects PE headers, sections, and calculates Shannon entropy (packer/crypter detection).
- Categorizes high-risk Win32 APIs (Process Injection, DPAPI Credential Theft, Keyloggers).
- Deobfuscates Base64 and PowerShell `-enc` stagers to reveal the raw payload.
- Extracts C2 URLs, public IPs, targeted browser paths, and crypto wallet extensions.
- Generates an AI-powered technical teardown explaining the full execution kill chain.

### 4. Correlated Triage (File + Message)
```bash
scamctl triage -f contract.pdf -m "Please sign this contract and run the verification utility."
```

### 5. Machine-Readable JSON Output
```bash
scamctl scan ./test.exe --json
scamctl reverse ./test.exe --json
```

---

## License
MIT
