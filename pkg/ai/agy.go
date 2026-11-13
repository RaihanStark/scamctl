package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type AgyProvider struct {
	Timeout time.Duration
}

func NewAgyProvider() *AgyProvider {
	return &AgyProvider{
		Timeout: 45 * time.Second,
	}
}

type agyEnvelope struct {
	Status   string `json:"status"`
	Response string `json:"response"`
}

func (a *AgyProvider) AnalyzeText(text string) (*AIAnalysisResult, error) {
	prompt := BuildTextPrompt(text)
	return a.callAgy(prompt)
}

func (a *AgyProvider) AnalyzeAttachmentContext(fileName string, detectedMime string, staticFindings []string, extractedText string, userContext string) (*AIAnalysisResult, error) {
	prompt := BuildAttachmentPrompt(fileName, detectedMime, staticFindings, extractedText, userContext)
	return a.callAgy(prompt)
}

func (a *AgyProvider) callAgy(prompt string) (*AIAnalysisResult, error) {
	agyPath, err := exec.LookPath("agy")
	if err != nil {
		return nil, errors.New("antigravity ('agy') CLI not found in PATH")
	}

	// Ensure no null bytes exist in arguments to prevent EINVAL from kernel
	cleanPrompt := strings.ReplaceAll(prompt, "\x00", "")

	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, agyPath, "-p", cleanPrompt, "--output-format", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("agy execution failed: %w, stderr: %s", err, stderr.String())
	}

	rawOutput := stdout.Bytes()

	// Try unmarshaling agy's envelope
	var envelope agyEnvelope
	var jsonContent string

	if err := json.Unmarshal(rawOutput, &envelope); err == nil && envelope.Response != "" {
		jsonContent = envelope.Response
	} else {
		jsonContent = string(rawOutput)
	}

	// Extract JSON block if wrapped in markdown
	cleanJSON := extractJSONString(jsonContent)

	var result AIAnalysisResult
	if err := json.Unmarshal([]byte(cleanJSON), &result); err != nil {
		return nil, fmt.Errorf("failed to parse AI response as JSON: %w (raw response: %s)", err, cleanJSON)
	}

	return &result, nil
}

var codeBlockRe = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*?\\})\\s*```")

func extractJSONString(raw string) string {
	raw = strings.TrimSpace(raw)
	// Check for markdown code fence
	if match := codeBlockRe.FindStringSubmatch(raw); len(match) > 1 {
		return strings.TrimSpace(match[1])
	}

	// Otherwise find first '{' and last '}'
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start != -1 && end != -1 && end > start {
		return raw[start : end+1]
	}

	return raw
}
