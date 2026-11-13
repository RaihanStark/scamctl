package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RaihanStark/scamctl/pkg/ai"
	"github.com/RaihanStark/scamctl/pkg/analyzer"
	"github.com/RaihanStark/scamctl/pkg/forensic"
	"github.com/RaihanStark/scamctl/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	triageFile string
	triageMsg  string
)

var triageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Cross-correlate a suspicious message and attachment together",
	RunE: func(cmd *cobra.Command, args []string) error {
		if triageFile == "" {
			return fmt.Errorf("please provide an attachment path using -f or --file")
		}
		if triageMsg == "" {
			return fmt.Errorf("please provide the accompanying message or job description using -m or --message")
		}

		if _, err := os.Stat(triageFile); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", triageFile)
		}

		if !jsonOutput {
			fmt.Printf("[*] Running combined triage on '%s' and message...\n", filepath.Base(triageFile))
		}

		// 1. Static Forensic Scan
		scanRes, err := forensic.ScanFile(triageFile)
		if err != nil {
			return fmt.Errorf("forensic scan failed: %w", err)
		}

		// 2. AI Correlated Intent Analysis
		if !jsonOutput {
			fmt.Println("[+] Correlating file metadata with message intent via Antigravity...")
		}

		var findingsSummary []string
		for _, f := range scanRes.Findings {
			findingsSummary = append(findingsSummary, fmt.Sprintf("[%s] %s: %s", f.Severity, f.Title, f.Description))
		}

		provider := ai.NewAgyProvider()
		aiRes, err := provider.AnalyzeAttachmentContext(
			scanRes.FileName,
			scanRes.DetectedMIME,
			findingsSummary,
			scanRes.ExtractedText,
			triageMsg,
		)

		rep := &analyzer.Report{
			TargetType:   "correlated_triage",
			TargetName:   filepath.Base(triageFile),
			StaticResult: scanRes,
		}

		aiScore := 0
		if err != nil {
			if !jsonOutput {
				fmt.Fprintf(os.Stderr, "[!] AI analysis warning: %v\n", err)
			}
		} else {
			rep.AIResult = aiRes
			aiScore = aiRes.RiskScore
		}

		rep.OverallScore = analyzer.ComputeCompositeScore(scanRes.BaseScore, aiScore)
		rep.Verdict = analyzer.CalculateVerdict(rep.OverallScore)

		if jsonOutput {
			data, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(data))
		} else {
			fmt.Print(ui.RenderReport(rep))
		}

		return nil
	},
}

func init() {
	triageCmd.Flags().StringVarP(&triageFile, "file", "f", "", "Path to the attachment file (required)")
	triageCmd.Flags().StringVarP(&triageMsg, "message", "m", "", "Accompanying message / email / proposal text (required)")
	_ = triageCmd.MarkFlagRequired("file")
	_ = triageCmd.MarkFlagRequired("message")
	rootCmd.AddCommand(triageCmd)
}
