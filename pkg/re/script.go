package re

import (
	"encoding/base64"
	"os"
	"regexp"
	"strings"
	"unicode/utf16"
)

var (
	// Matches PowerShell encodedcommand flags: -enc, -encodedcommand, -e
	rePSEncoded = regexp.MustCompile(`(?i)(?:-enc|-encodedcommand|-e)\s+([A-Za-z0-9+/=]{16,})`)
	// Generic large Base64 blobs
	reBase64Blob = regexp.MustCompile(`[A-Za-z0-9+/=]{32,}`)
)

// DeobfuscateScripts inspects script files and unmasks obfuscated payloads
func DeobfuscateScripts(path string, res *REResult) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)

	// 1. Look for PowerShell UTF-16LE encoded commands
	matches := rePSEncoded.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) > 1 {
			b64Str := m[1]
			decodedBytes, err := base64.StdEncoding.DecodeString(b64Str)
			if err == nil {
				// Convert UTF-16LE to string
				var u16s []uint16
				for i := 0; i+1 < len(decodedBytes); i += 2 {
					val := uint16(decodedBytes[i]) | (uint16(decodedBytes[i+1]) << 8)
					u16s = append(u16s, val)
				}
				decodedCmd := string(utf16.Decode(u16s))
				if len(decodedCmd) > 0 {
					res.DecodedPayloads = append(res.DecodedPayloads, DecodedPayload{
						Technique: "PowerShell UTF-16LE Base64 Deobfuscation",
						Content:   strings.TrimSpace(decodedCmd),
					})
					res.Capabilities = append(res.Capabilities, "Executes Obfuscated Base64 PowerShell Payload")
				}
			}
		}
	}

	// 2. Look for Generic ASCII Base64 blobs
	for _, blob := range reBase64Blob.FindAllString(content, 10) {
		decoded, err := base64.StdEncoding.DecodeString(blob)
		if err == nil && len(decoded) > 16 {
			// Check if decoded content looks like printable text or script
			isPrintable := true
			for _, b := range decoded {
				if b < 9 || (b > 13 && b < 32) || b > 126 {
					isPrintable = false
					break
				}
			}
			if isPrintable {
				decodedText := strings.TrimSpace(string(decoded))
				if strings.Contains(decodedText, "http") || strings.Contains(decodedText, "Invoke") ||
					strings.Contains(decodedText, "Download") || strings.Contains(decodedText, "cmd") {
					res.DecodedPayloads = append(res.DecodedPayloads, DecodedPayload{
						Technique: "Base64 Decoded Script Stream",
						Content:   decodedText,
					})
				}
			}
		}
	}

	return nil
}
