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

var scanCmd = &cobra.Command{
	Use:   "scan <file_path>",
	Short: "Scan a suspicious file or attachment for malware and deceptive indicators",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", filePath)
		}

		if !jsonOutput {
			fmt.Printf("🔍 Scanning attachment: %s...\n", filepath.Base(filePath))
		}

		// 1. Static Forensic Scan
		scanRes, err := forensic.ScanFile(filePath)
		if err != nil {
			return fmt.Errorf("forensic scan failed: %w", err)
		}

		rep := &analyzer.Report{
			TargetType:   "file",
			TargetName:   filepath.Base(filePath),
			StaticResult: scanRes,
		}

		aiScore := 0
		// 2. AI Analysis if enabled
		if !noAI {
			if !jsonOutput {
				fmt.Println("🧠 Running AI intent analysis via Antigravity...")
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
				"",
			)
			if err != nil {
				if !jsonOutput {
					fmt.Fprintf(os.Stderr, "⚠️  AI analysis warning: %v (falling back to forensic findings)\n", err)
				}
			} else {
				rep.AIResult = aiRes
				aiScore = aiRes.RiskScore
			}
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
	rootCmd.AddCommand(scanCmd)
}
