package ui

import (
	"fmt"
	"strings"

	"github.com/RaihanStark/scamctl/pkg/re"
	"github.com/charmbracelet/lipgloss"
)

func RenderREReport(res *re.REResult) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(titleStyle.Render(" SCAMCTL MALWARE REVERSE ENGINEERING REPORT ") + "\n\n")

	// Binary Overview
	b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Target:    "), valueStyle.Render(res.FileName)))
	b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("File Type: "), valueStyle.Render(res.FileType)))
	if res.TargetArch != "" {
		b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Arch:      "), valueStyle.Render(res.TargetArch)))
	}
	if res.Subsystem != "" {
		b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Subsystem: "), valueStyle.Render(res.Subsystem)))
	}
	if res.CompileTimestamp != "" {
		b.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Compiled:  "), valueStyle.Render(res.CompileTimestamp)))
	}

	// Detected Capabilities
	if len(res.Capabilities) > 0 {
		b.WriteString(sectionTitle.Render("--- Discovered Capabilities & Behavior -------------------") + "\n")
		for _, cap := range res.Capabilities {
			b.WriteString(fmt.Sprintf(" [!] %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#E74C3C")).Bold(true).Render(cap)))
		}
	}

	// Sections & Entropy
	if len(res.Sections) > 0 {
		b.WriteString(sectionTitle.Render("--- PE Section Analysis & Entropy ------------------------") + "\n")
		for _, s := range res.Sections {
			flag := ""
			nameStyle := lipgloss.NewStyle().Bold(true)
			if s.IsPacked {
				flag = lipgloss.NewStyle().Foreground(lipgloss.Color("#E67E22")).Render(" (HIGH ENTROPY / PACKED)")
			}
			b.WriteString(fmt.Sprintf(" * Section %-8s | Entropy: %4.2f/8.0 | RawSize: %7d bytes%s\n",
				nameStyle.Render(s.Name), s.Entropy, s.RawSize, flag))
		}
		if res.IsPacked {
			b.WriteString(fmt.Sprintf("   %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#E67E22")).Render("[!] High entropy indicates encrypted or packed code payload (crypter detected).")))
		}
	}

	// Suspicious Win32 APIs
	if len(res.SuspiciousAPIs) > 0 {
		b.WriteString(sectionTitle.Render("--- High-Risk Win32 API Imports --------------------------") + "\n")
		for _, api := range res.SuspiciousAPIs {
			cat := lipgloss.NewStyle().Foreground(lipgloss.Color("#F39C12")).Bold(true).Render("[" + api.Category + "]")
			b.WriteString(fmt.Sprintf(" %s %s!%s\n", cat, api.DLL, lipgloss.NewStyle().Bold(true).Render(api.Name)))
			b.WriteString(fmt.Sprintf("     %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#BBBBBB")).Render(api.Description)))
		}
	}

	// Deobfuscated Scripts / Payloads
	if len(res.DecodedPayloads) > 0 {
		b.WriteString(sectionTitle.Render("--- Deobfuscated In-Memory Payloads ----------------------") + "\n")
		for _, d := range res.DecodedPayloads {
			b.WriteString(fmt.Sprintf(" [+] Technique: %s\n", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D2D3")).Render(d.Technique)))
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#2ECC71")).Render("     "+d.Content) + "\n")
		}
	}

	// Indicators of Compromise
	if len(res.IoCs) > 0 {
		b.WriteString(sectionTitle.Render("--- Extracted Indicators of Compromise (IoCs) ------------") + "\n")
		for _, ioc := range res.IoCs {
			typeLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("#3498DB")).Bold(true).Render(fmt.Sprintf("%-28s", ioc.Type+":"))
			b.WriteString(fmt.Sprintf(" * %s %s\n", typeLabel, valueStyle.Render(ioc.Value)))
		}
	}

	// AI Technical Teardown
	if res.AIExplanation != "" {
		b.WriteString(sectionTitle.Render("--- AI Execution Flow & Kill Chain Teardown --------------") + "\n")
		b.WriteString(valueStyle.Render(res.AIExplanation) + "\n")
	}

	b.WriteString("\n")
	return b.String()
}
