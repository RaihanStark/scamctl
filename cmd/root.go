package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	jsonOutput bool
	noAI       bool
)

var rootCmd = &cobra.Command{
	Use:   "scamctl",
	Short: "scamctl - AI-Powered Scam & Malicious Attachment Detector",
	Long: `scamctl is a high-performance CLI tool for detecting scams, phishing,
and malicious file attachments before you open or execute them.

It combines static file forensics (magic byte inspection, double extensions, 
archive payloads, Office macros, PDF exploit actions) with AI intent analysis 
powered by Antigravity (agy).`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	rootCmd.PersistentFlags().BoolVar(&noAI, "no-ai", false, "Run static forensics only (skip AI analysis)")
}
