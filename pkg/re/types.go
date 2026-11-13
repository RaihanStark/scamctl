package re

type PESection struct {
	Name        string  `json:"name"`
	VirtualSize uint32  `json:"virtual_size"`
	RawSize     uint32  `json:"raw_size"`
	Entropy     float64 `json:"entropy"`
	IsPacked    bool    `json:"is_packed"`
}

type SuspiciousAPI struct {
	Name        string `json:"name"`
	DLL         string `json:"dll"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

type IoCEntry struct {
	Type  string `json:"type"`  // URL, IPv4, RegistryKey, BrowserTarget, CryptoTarget, Command
	Value string `json:"value"`
}

type DecodedPayload struct {
	Technique string `json:"technique"` // Base64, Hex, PowerShell Encoded
	Content   string `json:"content"`
}

type REResult struct {
	FilePath          string           `json:"file_path"`
	FileName          string           `json:"file_name"`
	FileType          string           `json:"file_type"`
	TargetArch        string           `json:"target_arch,omitempty"`
	Subsystem         string           `json:"subsystem,omitempty"`
	CompileTimestamp  string           `json:"compile_timestamp,omitempty"`
	IsPacked          bool             `json:"is_packed"`
	PackerHints       []string         `json:"packer_hints,omitempty"`
	Sections          []PESection      `json:"sections,omitempty"`
	SuspiciousAPIs    []SuspiciousAPI  `json:"suspicious_apis,omitempty"`
	IoCs              []IoCEntry       `json:"iocs,omitempty"`
	DecodedPayloads   []DecodedPayload `json:"decoded_payloads,omitempty"`
	Capabilities      []string         `json:"capabilities,omitempty"`
	ExtractedStrings  []string         `json:"extracted_strings,omitempty"`
	AIExplanation     string           `json:"ai_explanation,omitempty"`
}
