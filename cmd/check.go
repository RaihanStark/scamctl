package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/RaihanStark/scamctl/pkg/ai"
	"github.com/RaihanStark/scamctl/pkg/analyzer"
	"github.com/RaihanStark/scamctl/pkg/ui"
	"github.com/spf13/cobra"
)

var checkFile string

var checkCmd = &cobra.Command{
	Use:   "check [text_message]",
	Short: "Analyze a message, email, or proposal for scam and phishing patterns",
	RunE: func(cmd *cobra.Command, args []string) error {
		var content string

		if checkFile != "" {
			data, err := os.ReadFile(checkFile)
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}
			content = string(data)
		} else if len(args) > 0 {
			content = strings.Join(args, " ")
		} else {
			// Read from stdin if piped
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				bytes, err := io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %w", err)
				}
				content = string(bytes)
			} else {
				return fmt.Errorf("please provide text as argument, pass --file, or pipe input via stdin")
			}
		}

		content = strings.TrimSpace(content)
		if len(content) == 0 {
			return fmt.Errorf("input text is empty")
		}

		if !jsonOutput {
			fmt.Println("[+] Analyzing communication intent via Antigravity...")
		}

		provider := ai.NewAgyProvider()
		aiRes, err := provider.AnalyzeText(content)
		if err != nil {
			return fmt.Errorf("AI analysis failed: %w", err)
		}

		targetName := "Raw Text Input"
		if checkFile != "" {
			targetName = checkFile
		} else if len(content) > 40 {
			targetName = content[:40] + "..."
		}

		rep := &analyzer.Report{
			TargetType:   "communication",
			TargetName:   targetName,
			OverallScore: aiRes.RiskScore,
			Verdict:      analyzer.CalculateVerdict(aiRes.RiskScore),
			AIResult:     aiRes,
		}

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
	checkCmd.Flags().StringVarP(&checkFile, "file", "f", "", "Path to file containing email/message text")
	rootCmd.AddCommand(checkCmd)
}
