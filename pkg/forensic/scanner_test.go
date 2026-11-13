package forensic_test

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/RaihanStark/scamctl/pkg/forensic"
)

func TestDoubleExtensionDetection(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "invoice.pdf.exe")
	if err := os.WriteFile(filePath, []byte("fake binary content"), 0755); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	res, err := forensic.ScanFile(filePath)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if res.BaseScore < 50 {
		t.Errorf("expected BaseScore >= 50 for double extension, got %d", res.BaseScore)
	}

	foundDoubleExt := false
	for _, f := range res.Findings {
		if f.Title == "Double Extension Detected" {
			foundDoubleExt = true
			break
		}
	}

	if !foundDoubleExt {
		t.Errorf("expected finding 'Double Extension Detected', got: %+v", res.Findings)
	}
}

func TestArchiveWithDangerousExecutable(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "project_spec.zip")

	// Create a zip with a disguised bat script inside
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}

	zw := zip.NewWriter(zipFile)
	w, err := zw.Create("payload.scr")
	if err != nil {
		t.Fatalf("failed to create zip entry: %v", err)
	}
	_, _ = w.Write([]byte("start powershell.exe"))
	_ = zw.Close()
	_ = zipFile.Close()

	res, err := forensic.ScanFile(zipPath)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if !res.IsArchive {
		t.Errorf("expected IsArchive to be true")
	}

	foundPayload := false
	for _, f := range res.Findings {
		if f.Title == "Executable Payload Inside Archive" {
			foundPayload = true
			break
		}
	}

	if !foundPayload {
		t.Errorf("expected 'Executable Payload Inside Archive' finding, got: %+v", res.Findings)
	}
}

func TestWindowsPEHeaderInDisguisedFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "resume.pdf")

	// Write Windows MZ header
	mzBytes := []byte{'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}
	if err := os.WriteFile(filePath, mzBytes, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	res, err := forensic.ScanFile(filePath)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if !res.IsExecutable {
		t.Errorf("expected IsExecutable to be true for MZ header")
	}

	foundMZ := false
	for _, f := range res.Findings {
		if f.Category == "File Type Spoofing" {
			foundMZ = true
			break
		}
	}

	if !foundMZ {
		t.Errorf("expected File Type Spoofing finding for MZ header, got: %+v", res.Findings)
	}
}
