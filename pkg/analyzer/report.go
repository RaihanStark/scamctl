package analyzer

import (
	"github.com/RaihanStark/scamctl/pkg/ai"
	"github.com/RaihanStark/scamctl/pkg/forensic"
)

type Verdict string

const (
	VerdictSafe       Verdict = "SAFE"
	VerdictSuspicious Verdict = "SUSPICIOUS"
	VerdictHighRisk   Verdict = "HIGH RISK"
	VerdictCritical   Verdict = "CRITICAL / MALICIOUS"
)

type Report struct {
	TargetType     string                 `json:"target_type"` // "file", "text", "triage"
	TargetName     string                 `json:"target_name"`
	OverallScore   int                    `json:"overall_score"` // 0-100
	Verdict        Verdict                `json:"verdict"`
	StaticResult   *forensic.ScanResult   `json:"static_result,omitempty"`
	AIResult       *ai.AIAnalysisResult   `json:"ai_result,omitempty"`
	Recommendation string                 `json:"recommendation"`
}

func CalculateVerdict(score int) Verdict {
	switch {
	case score >= 80:
		return VerdictCritical
	case score >= 55:
		return VerdictHighRisk
	case score >= 25:
		return VerdictSuspicious
	default:
		return VerdictSafe
	}
}

func ComputeCompositeScore(staticScore int, aiScore int) int {
	if staticScore == 0 {
		return aiScore
	}
	if aiScore == 0 {
		return staticScore
	}

	maxScore := staticScore
	if aiScore > maxScore {
		maxScore = aiScore
	}

	// If either engine found high risk, respect the maximum
	if maxScore >= 75 {
		return maxScore
	}

	// Blended score
	blended := int(float64(maxScore)*0.7 + float64(staticScore+aiScore)/2.0*0.3)
	if blended > 100 {
		return 100
	}
	return blended
}
