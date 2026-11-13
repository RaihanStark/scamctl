package forensic

import (
	"os"
	"strings"
)

// ScanFile runs all static forensic checks on the given file.
func ScanFile(path string) (*ScanResult, error) {
	result, f, err := CheckMagicAndNaming(path)
	if err != nil {
		return nil, err
	}
	if f != nil {
		f.Close()
	}

	// Archive inspection
	if result.IsArchive {
		_ = InspectArchive(path, result)
	}

	// Office document inspection
	_ = InspectOfficeDocument(path, result)

	// PDF inspection
	_ = InspectPDF(path, result)

	// LNK inspection
	_ = InspectLNK(path, result)

	// If it's a plain text / script file (and not archive or binary executable), extract text
	if result.ExtractedText == "" && !result.IsArchive && !result.IsExecutable {
		if fi, err := os.Stat(path); err == nil && fi.Size() < 512*1024 {
			content, err := os.ReadFile(path)
			if err == nil {
				// Verify if it is primarily printable text
				isText := true
				for i := 0; i < len(content) && i < 1024; i++ {
					if content[i] == 0 {
						isText = false
						break
					}
				}
				if isText {
					s := strings.ToValidUTF8(string(content), "")
					s = strings.ReplaceAll(s, "\x00", "")
					if len(s) > 0 && len(s) < 50000 {
						result.ExtractedText = s
					}
				}
			}
		}
	}

	// Clamp BaseScore between 0 and 100
	if result.BaseScore > 100 {
		result.BaseScore = 100
	}

	return result, nil
}
