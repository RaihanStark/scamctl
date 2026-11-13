package forensic

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gabriel-vasile/mimetype"
)

// DangerousExtensions commonly used in malware lures
var DangerousExtensions = map[string]bool{
	".exe": true, ".scr": true, ".bat": true, ".cmd": true,
	".vbs": true, ".js":  true, ".wsf": true, ".ps1": true,
	".hta": true, ".cpl": true, ".msi": true, ".iso": true,
	".img": true, ".lnk": true, ".jar": true, ".dll": true,
}

// InnocentExtensions commonly faked
var InnocentExtensions = map[string]bool{
	".pdf": true, ".docx": true, ".doc": true, ".xlsx": true,
	".xls": true, ".pptx": true, ".txt": true, ".png":  true,
	".jpg": true, ".jpeg": true, ".mp4": true, ".zip":  true,
}

// CheckMagicAndNaming performs static checks on file name, extension, magic bytes and hashes.
func CheckMagicAndNaming(path string) (*ScanResult, *os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}

	// Calculate SHA-256
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		file.Close()
		return nil, nil, err
	}
	hashStr := hex.EncodeToString(hasher.Sum(nil))

	// Reset file pointer
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return nil, nil, err
	}

	fileName := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(fileName))

	result := &ScanResult{
		FilePath: path,
		FileName: fileName,
		FileSize: info.Size(),
		SHA256:   hashStr,
		Extension: ext,
		Findings: []Finding{},
	}

	// 1. Check for Right-to-Left Override (RLO) character \u202E
	if strings.ContainsRune(fileName, '\u202E') {
		result.Findings = append(result.Findings, Finding{
			Category:    "Obfuscation",
			Severity:    SeverityCritical,
			Title:       "Right-to-Left Override (RLO) Detected",
			Description: "The filename contains Unicode U+202E (RLO) which reverses characters to disguise the true extension in file managers.",
		})
		result.BaseScore += 60
	}

	// 2. Check for Double Extension (e.g. document.pdf.exe)
	parts := strings.Split(fileName, ".")
	if len(parts) > 2 {
		secondLast := "." + strings.ToLower(parts[len(parts)-2])
		last := "." + strings.ToLower(parts[len(parts)-1])

		if InnocentExtensions[secondLast] && DangerousExtensions[last] {
			result.Findings = append(result.Findings, Finding{
				Category:    "Extension Spoofing",
				Severity:    SeverityCritical,
				Title:       "Double Extension Detected",
				Description: "File appears disguised as '" + secondLast + "' but actually executes as '" + last + "'. This is a classic malware delivery technique.",
			})
			result.BaseScore += 50
		}
	}

	// 3. Check for Dangerous Extension directly
	if DangerousExtensions[ext] {
		result.IsExecutable = true
		result.Findings = append(result.Findings, Finding{
			Category:    "Executable",
			Severity:    SeverityHigh,
			Title:       "Direct Executable Extension",
			Description: "File has executable extension '" + ext + "'. Should never be opened from untrusted sources.",
		})
		result.BaseScore += 40
	}

	// 4. Detect MIME type via magic bytes
	mtype, err := mimetype.DetectFile(path)
	if err == nil && mtype != nil {
		result.DetectedMIME = mtype.String()

		// Check for Executable Magic Bytes disguised as non-executable
		isExecMime := strings.Contains(result.DetectedMIME, "x-dosexec") ||
			strings.Contains(result.DetectedMIME, "x-executable") ||
			strings.Contains(result.DetectedMIME, "x-msdownload") ||
			strings.Contains(result.DetectedMIME, "x-sharedlib")

		if isExecMime {
			result.IsExecutable = true
			if !DangerousExtensions[ext] {
				result.Findings = append(result.Findings, Finding{
					Category:    "File Type Spoofing",
					Severity:    SeverityCritical,
					Title:       "Executable Disguised as " + ext,
					Description: "Magic bytes indicate this is a binary executable (" + result.DetectedMIME + ") despite having extension '" + ext + "'.",
				})
				result.BaseScore += 60
			}
		}

		// Check if it's an archive
		if strings.Contains(result.DetectedMIME, "zip") ||
			strings.Contains(result.DetectedMIME, "x-tar") ||
			strings.Contains(result.DetectedMIME, "x-gzip") ||
			strings.Contains(result.DetectedMIME, "x-7z-compressed") ||
			strings.Contains(result.DetectedMIME, "x-rar") {
			result.IsArchive = true
		}
	}

	// Check for Windows MZ header manually if small file
	header := make([]byte, 2)
	_, _ = file.ReadAt(header, 0)
	if string(header) == "MZ" {
		result.IsExecutable = true
		if !DangerousExtensions[ext] {
			found := false
			for _, f := range result.Findings {
				if f.Title == "Executable Disguised as "+ext {
					found = true
					break
				}
			}
			if !found {
				result.Findings = append(result.Findings, Finding{
					Category:    "File Type Spoofing",
					Severity:    SeverityCritical,
					Title:       "Windows PE Binary Header (MZ) Detected",
					Description: "File begins with Windows executable MZ magic signature, but has extension '" + ext + "'.",
				})
				result.BaseScore += 60
			}
		}
	}

	return result, file, nil
}
