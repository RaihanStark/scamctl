package re

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func BuildREPrompt(res *REResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("TARGET FILE: %s\n", res.FileName))
	sb.WriteString(fmt.Sprintf("FILE TYPE: %s\n", res.FileType))
	if res.TargetArch != "" {
		sb.WriteString(fmt.Sprintf("ARCH: %s, SUBSYSTEM: %s\n", res.TargetArch, res.Subsystem))
	}
	if res.CompileTimestamp != "" {
		sb.WriteString(fmt.Sprintf("COMPILE TIME: %s\n", res.CompileTimestamp))
	}

	if len(res.Sections) > 0 {
		sb.WriteString("\nSECTIONS & ENTROPY:\n")
		for _, s := range res.Sections {
			packedFlag := ""
			if s.IsPacked {
				packedFlag = " [HIGH ENTROPY / PACKED]"
			}
			sb.WriteString(fmt.Sprintf("- %s: Entropy %.2f, RawSize %d%s\n", s.Name, s.Entropy, s.RawSize, packedFlag))
		}
	}

	if len(res.SuspiciousAPIs) > 0 {
		sb.WriteString("\nSUSPICIOUS API IMPORTS DETECTED:\n")
		for _, api := range res.SuspiciousAPIs {
			sb.WriteString(fmt.Sprintf("- %s (%s): %s\n", api.Name, api.Category, api.Description))
		}
	}

	if len(res.DecodedPayloads) > 0 {
		sb.WriteString("\nDEOBFUSCATED SCRIPTS / STAGERS:\n")
		for _, d := range res.DecodedPayloads {
			sb.WriteString(fmt.Sprintf("[%s]:\n%s\n", d.Technique, d.Content))
		}
	}

	if len(res.IoCs) > 0 {
		sb.WriteString("\nEXTRACTED INDICATORS OF COMPROMISE (IoCs):\n")
		for _, ioc := range res.IoCs {
			sb.WriteString(fmt.Sprintf("- [%s] %s\n", ioc.Type, ioc.Value))
		}
	}

	if len(res.ExtractedStrings) > 0 {
		sb.WriteString("\nKEY STRINGS FOUND IN BINARY:\n")
		limit := 20
		if len(res.ExtractedStrings) < limit {
			limit = len(res.ExtractedStrings)
		}
		for i := 0; i < limit; i++ {
			sb.WriteString(fmt.Sprintf("  %s\n", res.ExtractedStrings[i]))
		}
	}

	return fmt.Sprintf(`You are an expert malware reverse engineer and threat intelligence researcher.
Analyze the following extracted forensic artifacts from this suspicious binary/script.

Explain precisely HOW THIS MALWARE WORKS under the hood in a clean, structured technical teardown:
1. Malware Classification (e.g. Infostealer, Loader/Dropper, Keylogger, Ransomware, etc.)
2. Step-by-Step Execution Flow / Kill Chain:
   - Initial Execution & Evasion (how it hides, evades debuggers/sandboxes)
   - Memory Execution / Payload Staging (injection, unpacking, or script execution)
   - Data Theft / Malicious Objectives (what credentials, crypto wallets, or systems it targets)
   - Command & Control (C2) / Exfiltration (network traffic, server communication)
3. Technical Remediation (what to kill, registry keys or paths to scrub if infected).

Be concise, technical, and objective. Use bullet points and clear phase headers.

ARTIFACTS:
%s`, sb.String())
}

func ExplainMalwareWithAgy(res *REResult, timeout time.Duration) (string, error) {
	agyPath, err := exec.LookPath("agy")
	if err != nil {
		return "", errors.New("antigravity ('agy') CLI not found in PATH")
	}

	prompt := BuildREPrompt(res)
	prompt = strings.ReplaceAll(prompt, "\x00", "")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, agyPath, "-p", prompt, "--output-format", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("agy execution failed: %w, stderr: %s", err, stderr.String())
	}

	rawOutput := stdout.Bytes()

	type agyEnvelope struct {
		Response string `json:"response"`
	}

	var env agyEnvelope
	if err := json.Unmarshal(rawOutput, &env); err == nil && env.Response != "" {
		return strings.TrimSpace(env.Response), nil
	}

	return strings.TrimSpace(string(rawOutput)), nil
}
