package re

import (
	"bytes"
	"net"
	"os"
	"regexp"
	"strings"
	"unicode/utf16"
)

var (
	reURL      = regexp.MustCompile(`https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{5,}`)
	reIPv4     = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	reRegRun   = regexp.MustCompile(`(?i)(Software\\Microsoft\\Windows\\CurrentVersion\\Run[a-zA-Z0-9_\\]*)`)
	reBrowser  = regexp.MustCompile(`(?i)(\\(Google\\Chrome|Microsoft\\Edge|Brave-Browser|Mozilla\\Firefox)\\[a-zA-Z0-9_\\ -]+)`)
	reDPAPIDB  = regexp.MustCompile(`(?i)(Login Data|Web Data|Cookies|History|key4\.db|logins\.json)`)
	reCrypto   = regexp.MustCompile(`(?i)(nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|ibnejdfjmmkpcnlpebklmnkoeoihofec|Exodus|Atomic|CoinbaseWallet|metamask)`)
	reCmdExec  = regexp.MustCompile(`(?i)(powershell(\.exe)?|cmd(\.exe)?\s+/c|mshta(\.exe)?|rundll32(\.exe)?|certutil(\.exe)?|vssadmin(\.exe)?\s+delete\s+shadows)`)
)

// ExtractStringsAndIoCs extracts ASCII & UTF-16LE strings and identifies malware IoCs
func ExtractStringsAndIoCs(path string, res *REResult) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	asciiStrings := extractASCII(data, 4)
	unicodeStrings := extractUTF16LE(data, 4)

	allStrings := append(asciiStrings, unicodeStrings...)
	seenIoC := make(map[string]bool)

	for _, s := range allStrings {
		// URLs
		for _, u := range reURL.FindAllString(s, -1) {
			if !seenIoC[u] && !strings.Contains(u, "schemas.microsoft.com") && !strings.Contains(u, "w3.org") {
				seenIoC[u] = true
				res.IoCs = append(res.IoCs, IoCEntry{Type: "C2 / Remote URL", Value: u})
			}
		}

		// IPv4
		for _, ipStr := range reIPv4.FindAllString(s, -1) {
			ip := net.ParseIP(ipStr)
			if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() {
				if !seenIoC[ipStr] {
					seenIoC[ipStr] = true
					res.IoCs = append(res.IoCs, IoCEntry{Type: "Public IP (Potential C2)", Value: ipStr})
				}
			}
		}

		// Registry persistence
		for _, reg := range reRegRun.FindAllString(s, -1) {
			if !seenIoC[reg] {
				seenIoC[reg] = true
				res.IoCs = append(res.IoCs, IoCEntry{Type: "Registry Persistence Key", Value: reg})
				res.Capabilities = append(res.Capabilities, "Windows Boot Persistence via Registry Run Key")
			}
		}

		// Browser targets
		for _, b := range reBrowser.FindAllString(s, -1) {
			if !seenIoC[b] {
				seenIoC[b] = true
				res.IoCs = append(res.IoCs, IoCEntry{Type: "Targeted Browser Path", Value: b})
			}
		}

		// Database targets
		for _, db := range reDPAPIDB.FindAllString(s, -1) {
			if !seenIoC[db] {
				seenIoC[db] = true
				res.IoCs = append(res.IoCs, IoCEntry{Type: "Targeted Credential Database", Value: db})
			}
		}

		// Crypto targets
		for _, c := range reCrypto.FindAllString(s, -1) {
			if !seenIoC[c] {
				seenIoC[c] = true
				res.IoCs = append(res.IoCs, IoCEntry{Type: "Cryptocurrency Wallet Target", Value: c})
				res.Capabilities = append(res.Capabilities, "Targeting Cryptocurrency Wallets / Extensions")
			}
		}

		// Dangerous Commands
		for _, cmd := range reCmdExec.FindAllString(s, -1) {
			if !seenIoC[cmd] {
				seenIoC[cmd] = true
				res.IoCs = append(res.IoCs, IoCEntry{Type: "Process Spawn Command", Value: cmd})
			}
		}
	}

	// Keep a sample of interesting strings for AI reverse engineering prompt
	sampleLimit := 100
	var interesting []string
	for _, s := range allStrings {
		clean := strings.TrimSpace(s)
		if len(clean) >= 6 && len(clean) <= 120 {
			if strings.Contains(clean, "\\") || strings.Contains(clean, "/") ||
				strings.Contains(clean, "http") || strings.Contains(clean, "cmd") ||
				strings.Contains(clean, "token") || strings.Contains(clean, "pass") ||
				strings.Contains(clean, "bot") || strings.Contains(clean, "key") {
				interesting = append(interesting, clean)
				if len(interesting) >= sampleLimit {
					break
				}
			}
		}
	}
	res.ExtractedStrings = interesting

	return nil
}

func extractASCII(data []byte, minLen int) []string {
	var results []string
	var buf bytes.Buffer

	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\t' {
			buf.WriteByte(b)
		} else {
			if buf.Len() >= minLen {
				results = append(results, buf.String())
			}
			buf.Reset()
		}
	}
	if buf.Len() >= minLen {
		results = append(results, buf.String())
	}
	return results
}

func extractUTF16LE(data []byte, minLen int) []string {
	var results []string
	var u16s []uint16

	for i := 0; i+1 < len(data); i += 2 {
		val := uint16(data[i]) | (uint16(data[i+1]) << 8)
		if val >= 32 && val <= 126 {
			u16s = append(u16s, val)
		} else {
			if len(u16s) >= minLen {
				str := string(utf16.Decode(u16s))
				results = append(results, str)
			}
			u16s = u16s[:0]
		}
	}
	if len(u16s) >= minLen {
		str := string(utf16.Decode(u16s))
		results = append(results, str)
	}
	return results
}
