package re

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RaihanStark/scamctl/pkg/forensic"
)

// ReverseEngineer analyzes a suspicious binary or script to uncover its inner mechanics
func ReverseEngineer(targetPath string, enableAI bool) (*REResult, error) {
	fi, err := os.Stat(targetPath)
	if err != nil {
		return nil, err
	}

	res := &REResult{
		FilePath: targetPath,
		FileName: filepath.Base(targetPath),
		FileType: "Unknown / Binary",
	}

	workingPath := targetPath
	var tempDir string

	// If it's a zip archive, extract first executable entry to a safe temp folder for reverse engineering
	ext := strings.ToLower(filepath.Ext(targetPath))
	if ext == ".zip" {
		extractedPath, dir, err := extractPayloadFromZip(targetPath)
		if err == nil && extractedPath != "" {
			workingPath = extractedPath
			tempDir = dir
			defer os.RemoveAll(tempDir)
			res.FileName = filepath.Base(extractedPath) + fmtInZip(filepath.Base(targetPath))
		}
	}

	// 1. Check if Windows PE binary (MZ header)
	isPE := false
	header := make([]byte, 2)
	f, err := os.Open(workingPath)
	if err == nil {
		_, _ = f.Read(header)
		f.Close()
		if string(header) == "MZ" {
			isPE = true
		}
	}

	if isPE {
		_ = AnalyzePE(workingPath, res)
	} else {
		// Identify script / other
		if ext == ".ps1" || ext == ".bat" || ext == ".cmd" || ext == ".vbs" || ext == ".js" || ext == ".lnk" {
			res.FileType = strings.ToUpper(ext[1:]) + " Script / Stager"
		} else {
			res.FileType = "Data / Script Payload"
		}
	}

	// 2. Extract strings & IoCs
	_ = ExtractStringsAndIoCs(workingPath, res)

	// 3. Deobfuscate scripts / base64 payloads
	_ = DeobfuscateScripts(workingPath, res)

	// 4. Run AI Teardown if requested
	if enableAI {
		explanation, err := ExplainMalwareWithAgy(res, 60*time.Second)
		if err == nil {
			res.AIExplanation = explanation
		}
	}

	_ = fi
	return res, nil
}

func fmtInZip(zipName string) string {
	return " (extracted from " + zipName + ")"
}

func extractPayloadFromZip(zipPath string) (string, string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", "", err
	}
	defer r.Close()

	for _, f := range r.File {
		entryExt := strings.ToLower(filepath.Ext(f.Name))
		if forensic.DangerousExtensions[entryExt] || strings.Contains(f.Name, ".exe") || strings.Contains(f.Name, ".scr") {
			// Found payload inside
			tmpDir, err := os.MkdirTemp("", "scamctl-re-*")
			if err != nil {
				return "", "", err
			}

			destPath := filepath.Join(tmpDir, filepath.Base(f.Name))
			rc, err := f.Open()
			if err != nil {
				os.RemoveAll(tmpDir)
				return "", "", err
			}

			out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				rc.Close()
				os.RemoveAll(tmpDir)
				return "", "", err
			}

			// Limit decompression to 50MB to prevent zip bombs
			_, _ = io.Copy(out, io.LimitReader(rc, 50*1024*1024))
			out.Close()
			rc.Close()

			return destPath, tmpDir, nil
		}
	}

	return "", "", nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
