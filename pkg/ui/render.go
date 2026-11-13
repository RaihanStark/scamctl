package ui

import (
	"fmt"
	"strings"

	"github.com/RaihanStark/scamctl/pkg/analyzer"
	"github.com/RaihanStark/scamctl/pkg/forensic"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#5A56E0")).
			Padding(0, 1)

	headerBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#5A56E0")).
			Padding(0, 1).
			MarginBottom(1)

	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#888888"))

	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E0E0E0"))

	safeBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(lipgloss.Color("#2ECC71")).
			Padding(0, 1)

	suspiciousBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(lipgloss.Color("#F39C12")).
			Padding(0, 1)

	highRiskBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#E67E22")).
			Padding(0, 1)

	criticalBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#E74C3C")).
			Padding(0, 1)

	sectionTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00D2D3")).
			MarginTop(1).
			MarginBottom(0)

	recommendationBox = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("#E74C3C")).
				Padding(0, 1).
				MarginTop(1)
)

func RenderReport(rep *analyzer.Report) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(titleStyle.Render(" SCAMCTL SECURITY REPORT ") + "\n\n")

	// Target info
	b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Target: "), valueStyle.Render(rep.TargetName)))
	b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Type:   "), valueStyle.Render(rep.TargetType)))

	if rep.StaticResult != nil {
		if rep.StaticResult.DetectedMIME != "" {
			b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("MIME:   "), valueStyle.Render(rep.StaticResult.DetectedMIME)))
		}
		if rep.StaticResult.SHA256 != "" {
			b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("SHA256: "), valueStyle.Render(rep.StaticResult.SHA256)))
		}
	}

	b.WriteString("\n")

	// Verdict & Score
	verdictBadge := formatBadge(rep.Verdict)
	scoreBar := renderScoreBar(rep.OverallScore)
	b.WriteString(fmt.Sprintf("%s %s  %s\n", labelStyle.Render("Verdict:"), verdictBadge, scoreBar))

	// Forensic Findings
	if rep.StaticResult != nil && len(rep.StaticResult.Findings) > 0 {
		b.WriteString(sectionTitle.Render("── Forensic File Findings ───────────────────────────") + "\n")
		for _, f := range rep.StaticResult.Findings {
			sevBadge := formatSeverity(f.Severity)
			b.WriteString(fmt.Sprintf(" %s %s\n", sevBadge, lipgloss.NewStyle().Bold(true).Render(f.Title)))
			b.WriteString(fmt.Sprintf("   %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#BBBBBB")).Render(f.Description)))
		}
	}

	// URLs if any
	if rep.StaticResult != nil && len(rep.StaticResult.ExtractedURLs) > 0 {
		b.WriteString(sectionTitle.Render("── Extracted URLs ───────────────────────────────────") + "\n")
		for _, u := range rep.StaticResult.ExtractedURLs {
			b.WriteString(fmt.Sprintf(" • %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#3498DB")).Render(u)))
		}
	}

	// AI Intent Analysis
	if rep.AIResult != nil {
		b.WriteString(sectionTitle.Render("── AI Intent & Social Engineering ───────────────────") + "\n")
		if rep.AIResult.Summary != "" {
			b.WriteString(fmt.Sprintf(" %s\n", valueStyle.Render(rep.AIResult.Summary)))
		}

		if len(rep.AIResult.Tactics) > 0 {
			b.WriteString("\n " + labelStyle.Render("Tactics Identified:") + "\n")
			for _, t := range rep.AIResult.Tactics {
				b.WriteString(fmt.Sprintf("  • %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#E74C3C")).Render(t)))
			}
		}

		if len(rep.AIResult.RedFlags) > 0 {
			b.WriteString("\n " + labelStyle.Render("Red Flags / Deceptive Cues:") + "\n")
			for _, rf := range rep.AIResult.RedFlags {
				b.WriteString(fmt.Sprintf("  ⚠ %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#F1C40F")).Render(rf)))
			}
		}
	}

	// Recommendation
	rec := rep.Recommendation
	if rec == "" && rep.AIResult != nil {
		rec = rep.AIResult.Recommendation
	}
	if rec == "" {
		if rep.OverallScore >= 55 {
			rec = "DO NOT open, execute, or follow instructions in this file/message. Delete it immediately."
		} else {
			rec = "No immediate threats detected. Proceed with normal caution."
		}
	}

	boxStyle := recommendationBox
	if rep.OverallScore < 25 {
		boxStyle = boxStyle.BorderForeground(lipgloss.Color("#2ECC71"))
	} else if rep.OverallScore < 55 {
		boxStyle = boxStyle.BorderForeground(lipgloss.Color("#F39C12"))
	}

	b.WriteString("\n" + boxStyle.Render(fmt.Sprintf("ACTIONABLE ADVICE:\n%s", rec)) + "\n\n")

	return b.String()
}

func formatBadge(v analyzer.Verdict) string {
	switch v {
	case analyzer.VerdictCritical:
		return criticalBadge.Render("✖ CRITICAL / MALICIOUS")
	case analyzer.VerdictHighRisk:
		return highRiskBadge.Render("▲ HIGH RISK")
	case analyzer.VerdictSuspicious:
		return suspiciousBadge.Render("⚠ SUSPICIOUS")
	default:
		return safeBadge.Render("✓ SAFE")
	}
}

func formatSeverity(s forensic.Severity) string {
	switch s {
	case forensic.SeverityCritical:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#E74C3C")).Bold(true).Render("[CRITICAL]")
	case forensic.SeverityHigh:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#E67E22")).Bold(true).Render("[HIGH]")
	case forensic.SeverityMedium:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#F39C12")).Bold(true).Render("[MED]")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#3498DB")).Render("[INFO]")
	}
}

func renderScoreBar(score int) string {
	width := 20
	filled := (score * width) / 100
	if filled > width {
		filled = width
	}
	empty := width - filled

	fillColor := "#2ECC71"
	if score >= 80 {
		fillColor = "#E74C3C"
	} else if score >= 55 {
		fillColor = "#E67E22"
	} else if score >= 25 {
		fillColor = "#F39C12"
	}

	barFilled := lipgloss.NewStyle().Foreground(lipgloss.Color(fillColor)).Render(strings.Repeat("█", filled))
	barEmpty := lipgloss.NewStyle().Foreground(lipgloss.Color("#444444")).Render(strings.Repeat("░", empty))

	return fmt.Sprintf("[%s%s] %d/100", barFilled, barEmpty, score)
}
