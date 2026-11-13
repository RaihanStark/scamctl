package ai

type AIAnalysisResult struct {
	RiskScore      int      `json:"risk_score"` // 0-100
	Verdict        string   `json:"verdict"`    // SAFE, SUSPICIOUS, HIGH_RISK, MALICIOUS
	Confidence     string   `json:"confidence"` // LOW, MEDIUM, HIGH
	Tactics        []string `json:"tactics"`
	RedFlags       []string `json:"red_flags"`
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation"`
}

type Provider interface {
	AnalyzeText(text string) (*AIAnalysisResult, error)
	AnalyzeAttachmentContext(fileName string, detectedMime string, staticFindings []string, extractedText string, userContext string) (*AIAnalysisResult, error)
}
