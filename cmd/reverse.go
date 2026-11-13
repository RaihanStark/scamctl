package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RaihanStark/scamctl/pkg/re"
	"github.com/RaihanStark/scamctl/pkg/ui"
	"github.com/spf13/cobra"
)

var reverseCmd = &cobra.Command{
	Use:   "reverse <file_path>",
	Short: "Reverse engineer a suspicious malware file to understand how it operates",
	Long: `Dissects a suspicious binary, executable, or script.

Extracts architecture, PE sections & entropy (packer detection), high-risk Win32 API 
calls (process injection, DPAPI credential theft, keylogging), deobfuscates Base64/PowerShell
stagers, extracts C2 URLs, and generates an AI-powered technical teardown explaining 
how the malware works under the hood.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", filePath)
		}

		if !jsonOutput {
			fmt.Printf("[*] Reverse engineering target: %s...\n", filepath.Base(filePath))
			if !noAI {
				fmt.Println("[+] Generating technical execution flow & kill chain analysis via Antigravity...")
			}
		}

		res, err := re.ReverseEngineer(filePath, !noAI)
		if err != nil {
			return fmt.Errorf("reverse engineering failed: %w", err)
		}

		if jsonOutput {
			data, err := json.MarshalIndent(res, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(data))
		} else {
			fmt.Print(ui.RenderREReport(res))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(reverseCmd)
}
