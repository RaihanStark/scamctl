package forensic

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	lnkHeader = []byte{0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00}
	reSuspiciousCmd = regexp.MustCompile(`(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|curl|certutil|bitsadmin|regsvr32|bash|sh)`)
	reDownloadOrExec = regexp.MustCompile(`(?i)(Invoke-WebRequest|iwr|curl|wget|DownloadFile|DownloadString|iex|Invoke-Expression|-enc|-encodedcommand|-w\s+hidden)`)
)

// InspectLNK inspects Windows Shortcut (.lnk) files for hidden commands
func InspectLNK(path string, res *ScanResult) error {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".lnk" && !strings.Contains(res.DetectedMIME, "x-ms-shortcut") {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	isLNK := false
	if len(data) >= 8 && bytes.Equal(data[:8], lnkHeader) {
		isLNK = true
	} else if ext == ".lnk" {
		isLNK = true
	}

	if !isLNK {
		return nil
	}

	contentStr := string(data)
	var matchedCmds []string
	var matchedExecs []string

	for _, match := range reSuspiciousCmd.FindAllString(contentStr, -1) {
		matchedCmds = append(matchedCmds, strings.ToLower(match))
	}

	for _, match := range reDownloadOrExec.FindAllString(contentStr, -1) {
		matchedExecs = append(matchedExecs, strings.ToLower(match))
	}

	res.Findings = append(res.Findings, Finding{
		Category:    "Shortcut Abuse",
		Severity:    SeverityCritical,
		Title:       "Windows Shortcut (.lnk) File",
		Description: "LNK shortcuts are widely used in social engineering to execute hidden scripts while displaying an innocent document icon.",
	})
	res.BaseScore += 40

	if len(matchedCmds) > 0 {
		res.Findings = append(res.Findings, Finding{
			Category:    "Malicious Command Execution",
			Severity:    SeverityCritical,
			Title:       "Shell / Script Engine Invocations in Shortcut",
			Description: fmt.Sprintf("LNK targets suspicious binaries: %s", strings.Join(matchedCmds, ", ")),
		})
		res.BaseScore += 50
	}

	if len(matchedExecs) > 0 {
		res.Findings = append(res.Findings, Finding{
			Category:    "Remote Dropper / Stager",
			Severity:    SeverityCritical,
			Title:       "Obfuscated Payload Downloader Detected",
			Description: fmt.Sprintf("LNK contains downloader/execution primitives: %s", strings.Join(matchedExecs, ", ")),
		})
		res.BaseScore += 60
	}

	return nil
}
