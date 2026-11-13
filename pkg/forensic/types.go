package forensic

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Finding struct {
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
}

type ScanResult struct {
	FilePath         string    `json:"file_path"`
	FileName         string    `json:"file_name"`
	FileSize         int64     `json:"file_size"`
	SHA256           string    `json:"sha256"`
	DetectedMIME     string    `json:"detected_mime"`
	ExpectedMIME     string    `json:"expected_mime"`
	Extension        string    `json:"extension"`
	IsArchive        bool      `json:"is_archive"`
	IsExecutable     bool      `json:"is_executable"`
	IsEncrypted      bool      `json:"is_encrypted"`
	Findings         []Finding `json:"findings"`
	ExtractedText    string    `json:"extracted_text,omitempty"`
	ExtractedURLs    []string  `json:"extracted_urls,omitempty"`
	BaseScore        int       `json:"base_score"` // 0 - 100 based on static findings
}
