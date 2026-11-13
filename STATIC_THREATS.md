# Static Threat Detection Reference

This document outlines all technical threats, file manipulations, and exploit indicators detected by **`scamctl`'s static forensic engine**—completely independent of AI semantic analysis.

These checks run locally, offline, and in zero-execution mode (inspecting byte headers, archive tables, and file structures without running untrusted code).

---

## Threat Matrix Overview

| Category | Threat Vector | Technical Mechanism | Risk Level |
| :--- | :--- | :--- | :--- |
| **Naming & Masquerading** | Double Extension | `Contract.pdf.exe` masquerading as document | **CRITICAL** |
| | Unicode RLO Override | U+202E character reversing extension display order | **CRITICAL** |
| | Direct Executables | Unsolicited binary formats (`.exe`, `.scr`, `.bat`, etc.) | **HIGH** |
| **Magic Byte Verification** | True MIME Mismatch | Magic bytes identify PE binary despite `.pdf`/`.png` extension | **CRITICAL** |
| | Windows PE Header | Direct `MZ` signature (`0x4D 0x5A`) in disguised files | **CRITICAL** |
| **Archive Weaponization** | Password Protection | Encrypted ZIP entries to evade platform/email virus scanners | **HIGH** |
| | Embedded Payloads | Executables nested inside innocent-looking `.zip`/`.tar` | **CRITICAL** |
| | Zip Slip (Traversal) | Entries containing `../` relative path traversal | **CRITICAL** |
| | Zip Bomb (DoS) | Compression ratio > 100:1 with high uncompressed size | **CRITICAL** |
| | Hidden Dotfiles | Concealed files starting with `.` inside archives | **MEDIUM** |
| **Office Documents** | VBA Macro Code | Embedded executable `vbaProject.bin` in OpenXML documents | **CRITICAL** |
| | Remote Template Injection | External `attachedTemplate` rels pointing to remote `.dotm` | **CRITICAL** |
| **PDF Exploit Primitives** | `/Launch` Action | PDF directive commanding the OS to launch an external process | **CRITICAL** |
| | Auto-Execution `/OpenAction` | Automatic execution of script/action upon opening document | **CRITICAL** |
| | Embedded `/JavaScript` | Active scripting engine payload inside PDF objects | **HIGH** |
| | `/EmbeddedFiles` Dropper | Hidden file payloads embedded inside PDF object streams | **MEDIUM** |
| **Windows Shortcuts** | LNK Binary Masquerading | Shortcut with document icon targeting system script engines | **CRITICAL** |
| | Obfuscated Downloader | LNK calling `powershell -w hidden -enc`, `mshta`, or `curl` | **CRITICAL** |

---

## Detailed Technical Explanations

### 1. Filename & Extension Spoofing

#### A. Double Extension Attack
* **How It Works:** Operating systems like Windows by default hide known file extensions. Threat actors name files `Project_Brief.pdf.exe`. To the victim, the file displays as `Project_Brief.pdf`, but double-clicking executes the `.exe` binary.
* **Detection:** `scamctl` checks if the penultimate token matches an innocent document format (`.pdf`, `.docx`, `.xlsx`, `.png`, etc.) while the final extension is an executable or script (`.exe`, `.scr`, `.bat`, `.cmd`, `.vbs`, `.js`, `.ps1`, `.lnk`, etc.).

#### B. Right-to-Left Override (RLO) Injection
* **How It Works:** Unicode character `U+202E` instructs the text renderer to display subsequent characters in reverse order. A malicious file named `Requirements\u202Efdp.exe` is visually displayed in file managers as `Requirementsexe.pdf`, misleading the victim into treating it as a PDF.
* **Detection:** Scans filenames for the presence of the `\u202E` rune and immediately flags it as critical obfuscation.

---

### 2. File Header & Magic Byte Discrepancy

* **How It Works:** Attackers frequently rename executable files directly (e.g. renaming `malware.exe` to `photo.png` or `resume.pdf`) hoping victims will attempt to open them, or to bypass basic extension-only upload validation rules.
* **Detection:**
  * Uses pure-Go MIME sniffing (`github.com/gabriel-vasile/mimetype`) to read the file's binary magic numbers rather than trusting its file extension.
  * Explicitly inspects the initial bytes for the Windows Portable Executable (PE) signature `MZ` (`0x4D 0x5A`).
  * If a file claiming to be `.pdf`, `.docx`, or an image actually contains `application/x-dosexec`, `application/x-executable`, or `application/x-sharedlib`, `scamctl` raises a Critical File Type Spoofing alert.

---

### 3. Archive Weaponization (.zip, .tar, .tgz)

`scamctl` inspects archives safely in-memory without unpacking untrusted files to disk:

* **Password-Protected Archives:** Attackers frequently put malware in password-protected archives (e.g., `job_spec_pass123.zip`) and provide the password in the chat. This prevents automated security scanners (e.g., Upwork, Gmail, VirusTotal gateways) from inspecting the payload. `scamctl` detects the encrypted entry flag (Bit 0 of general-purpose flags) and flags it as a high-risk indicator.
* **Payload Traps:** Inspects the file table inside the archive to flag dangerous payloads (`.exe`, `.scr`, `.bat`, `.lnk`, etc.) nested inside what was promised as a document bundle.
* **Zip Slip / Path Traversal:** Detects entries containing directory traversal sequences (such as `../../../../etc/passwd` or `..\..\..\AppData\...`) designed to overwrite system files when unpacked by vulnerable archive tools.
* **Zip Bomb Detection:** Calculates the ratio of uncompressed size to compressed size. Ratios exceeding 100:1 with total uncompressed volume exceeding 100 MB are flagged as decompression bombs.

---

### 4. Microsoft Office Document Forensics

Modern Microsoft Office files (`.docx`, `.xlsx`, `.pptx`) are OpenXML zip containers. `scamctl` parses their internal structures:

* **VBA Macros (`vbaProject.bin`):** Attackers use Visual Basic for Applications (VBA) macros to run PowerShell stagers or install infostealers. `scamctl` detects the presence of `word/vbaProject.bin`, `xl/vbaProject.bin`, or `ppt/vbaProject.bin`.
* **Remote Template Injection:** A stealthier technique where the document itself contains no local macro code. Instead, its internal relationship file (`_rels/*.rels`) specifies an external remote template (`TargetMode="External"` and `Type="...attachedTemplate"` pointing to an external HTTP URL or `.dotm` file). When the document is opened, Office automatically fetches and executes the remote macro template.

---

### 5. PDF Exploit Primitives

PDFs support rich functionality that attackers weaponize:

* **`/Launch` Action:** Instructs the PDF viewer to execute an external application or shell command on the host operating system.
* **`/JavaScript` and `/JS`:** Embedded JavaScript scripts often used in heap-spray exploits or to trigger phishing redirects.
* **`/OpenAction` and `/AA`:** Automatic trigger events that run embedded actions or scripts the moment the document is loaded, requiring zero interaction from the victim.
* **`/EmbeddedFiles`:** Files packed directly inside the PDF stream to evade perimeter file filters and act as a malware dropper.

---

### 6. Windows Shortcut (.lnk) Abuse

Windows `.lnk` shortcuts are one of the most common vectors for delivering infostealers (e.g. LummaC2, RedLine):

* **Mechanism:** The shortcut uses a benign icon (such as a PDF or folder icon) while its binary target points to native Windows system binaries like `powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe`, or `curl.exe`.
* **Detection:**
  * Confirms the binary ShellLinkHeader signature (`0x00021401` CLSID).
  * Scans shortcut arguments for process spawning patterns and encoded downloaders (e.g., `-enc`, `-w hidden`, `Invoke-WebRequest`, `DownloadFile`, `iex`).
