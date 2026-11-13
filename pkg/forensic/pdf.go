package forensic

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reJS         = regexp.MustCompile(`/(JavaScript|JS)\b`)
	reLaunch     = regexp.MustCompile(`/Launch\b`)
	reOpenAction = regexp.MustCompile(`/(OpenAction|AA)\b`)
	reEmbedded   = regexp.MustCompile(`/EmbeddedFiles\b`)
	reURI        = regexp.MustCompile(`/URI\s*\(([^)]+)\)`)
)

// InspectPDF scans a PDF file for malicious objects and exploits
func InspectPDF(path string, res *ScanResult) error {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".pdf" && !strings.Contains(res.DetectedMIME, "pdf") {
		return nil
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read content (limit to reasonable size for scanning object dictionaries)
	buf, err := io.ReadAll(io.LimitReader(file, 25*1024*1024))
	if err != nil {
		return err
	}

	var hasJS bool
	var hasLaunch bool
	var hasAutoExec bool
	var hasEmbedded bool

	if reJS.Match(buf) {
		hasJS = true
	}
	if reLaunch.Match(buf) {
		hasLaunch = true
	}
	if reOpenAction.Match(buf) {
		hasAutoExec = true
	}
	if reEmbedded.Match(buf) {
		hasEmbedded = true
	}

	// Extract URIs
	matches := reURI.FindAllSubmatch(buf, 20)
	for _, m := range matches {
		if len(m) > 1 {
			u := string(m[1])
			if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
				res.ExtractedURLs = append(res.ExtractedURLs, u)
			}
		}
	}

	if hasLaunch {
		res.Findings = append(res.Findings, Finding{
			Category:    "PDF Exploit Primitive",
			Severity:    SeverityCritical,
			Title:       "Dangerous /Launch Action Detected",
			Description: "PDF contains a /Launch action designed to execute external commands or programs upon opening.",
		})
		res.BaseScore += 65
	}

	if hasJS {
		res.Findings = append(res.Findings, Finding{
			Category:    "PDF Scripting",
			Severity:    SeverityHigh,
			Title:       "Embedded JavaScript (/JavaScript)",
			Description: "PDF contains active embedded JavaScript scripts, commonly used in PDF reader exploits or deceptive redirects.",
		})
		res.BaseScore += 40
	}

	if hasAutoExec && (hasJS || hasLaunch) {
		res.Findings = append(res.Findings, Finding{
			Category:    "PDF Auto-Execution",
			Severity:    SeverityCritical,
			Title:       "Auto-Execution on Document Open (/OpenAction)",
			Description: "PDF is configured to automatically run embedded scripts or actions the moment the document is viewed without user interaction.",
		})
		res.BaseScore += 45
	}

	if hasEmbedded {
		res.Findings = append(res.Findings, Finding{
			Category:    "PDF Dropper",
			Severity:    SeverityMedium,
			Title:       "Embedded Files in PDF (/EmbeddedFiles)",
			Description: "PDF contains embedded file attachments, a technique often used to drop secondary payloads.",
		})
		res.BaseScore += 25
	}

	// Extract readable strings for AI analysis
	text := extractReadableStrings(buf, 1000)
	if len(text) > 0 {
		res.ExtractedText = text
	}

	return nil
}

func extractReadableStrings(data []byte, maxLines int) string {
	var lines []string
	var cur bytes.Buffer

	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\t' {
			cur.WriteByte(b)
		} else {
			if cur.Len() >= 5 {
				s := strings.TrimSpace(cur.String())
				if len(s) > 8 && !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "<") {
					lines = append(lines, s)
					if len(lines) >= maxLines {
						break
					}
				}
			}
			cur.Reset()
		}
	}

	return strings.Join(lines, "\n")
}
