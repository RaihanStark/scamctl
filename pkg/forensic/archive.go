package forensic

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// InspectArchive safely inspects zip and tar archives without writing contents to disk.
func InspectArchive(path string, res *ScanResult) error {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".zip" || strings.Contains(res.DetectedMIME, "zip") {
		return inspectZip(path, res)
	} else if ext == ".tar" || ext == ".gz" || ext == ".tgz" || strings.Contains(res.DetectedMIME, "tar") || strings.Contains(res.DetectedMIME, "gzip") {
		return inspectTarGz(path, res)
	}
	return nil
}

func inspectZip(path string, res *ScanResult) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()

	var totalUncompressed uint64
	var totalCompressed uint64
	var dangerousFiles []string
	var hiddenFiles []string
	var encryptedFiles []string

	for _, f := range r.File {
		entryName := f.Name
		entryExt := strings.ToLower(filepath.Ext(entryName))

		totalUncompressed += f.UncompressedSize64
		totalCompressed += f.CompressedSize64

		// 1. Check for Password / Encryption
		// Bit 0 of Flags is the general purpose bit flag for encryption
		if f.Flags&0x1 != 0 {
			res.IsEncrypted = true
			encryptedFiles = append(encryptedFiles, entryName)
		}

		// 2. Check for Zip Slip / Path Traversal
		if strings.Contains(entryName, "..") {
			res.Findings = append(res.Findings, Finding{
				Category:    "Archive Security",
				Severity:    SeverityCritical,
				Title:       "Zip Slip / Directory Traversal Detected",
				Description: fmt.Sprintf("Archive contains relative path '%s' which can overwrite system files when unpacked.", entryName),
			})
			res.BaseScore += 60
		}

		// 3. Check for Dangerous Extensions inside archive
		if DangerousExtensions[entryExt] {
			dangerousFiles = append(dangerousFiles, fmt.Sprintf("%s (%s)", entryName, entryExt))
		}

		// 4. Double extensions inside archive
		parts := strings.Split(filepath.Base(entryName), ".")
		if len(parts) > 2 {
			secondLast := "." + strings.ToLower(parts[len(parts)-2])
			last := "." + strings.ToLower(parts[len(parts)-1])
			if InnocentExtensions[secondLast] && DangerousExtensions[last] {
				res.Findings = append(res.Findings, Finding{
					Category:    "Extension Spoofing",
					Severity:    SeverityCritical,
					Title:       "Disguised File Inside Archive",
					Description: fmt.Sprintf("Archive entry '%s' uses double extension to disguise executable payload.", entryName),
				})
				res.BaseScore += 50
			}
		}

		// 5. Hidden files inside archive
		base := filepath.Base(entryName)
		if strings.HasPrefix(base, ".") && len(base) > 1 {
			hiddenFiles = append(hiddenFiles, entryName)
		}
	}

	if res.IsEncrypted {
		res.Findings = append(res.Findings, Finding{
			Category:    "Archive Security",
			Severity:    SeverityHigh,
			Title:       "Password-Protected Archive",
			Description: fmt.Sprintf("Archive is encrypted with password (%d entries). Threat actors frequently password-protect files to evade automated email/platform virus scanners.", len(encryptedFiles)),
		})
		res.BaseScore += 45
	}

	if len(dangerousFiles) > 0 {
		res.Findings = append(res.Findings, Finding{
			Category:    "Archive Security",
			Severity:    SeverityCritical,
			Title:       "Executable Payload Inside Archive",
			Description: fmt.Sprintf("Archive contains %d executable/script file(s): %s", len(dangerousFiles), strings.Join(dangerousFiles, ", ")),
		})
		res.BaseScore += 55
	}

	if len(hiddenFiles) > 0 {
		res.Findings = append(res.Findings, Finding{
			Category:    "Archive Security",
			Severity:    SeverityMedium,
			Title:       "Hidden File(s) in Archive",
			Description: fmt.Sprintf("Archive contains hidden dotfiles: %s", strings.Join(hiddenFiles, ", ")),
		})
		res.BaseScore += 15
	}

	// 6. Zip Bomb check (ratio > 100:1 and uncompressed > 100MB)
	if totalCompressed > 0 && totalUncompressed > 100*1024*1024 {
		ratio := totalUncompressed / totalCompressed
		if ratio > 100 {
			res.Findings = append(res.Findings, Finding{
				Category:    "Denial of Service",
				Severity:    SeverityCritical,
				Title:       "Potential Zip Bomb / Decompression Bomb",
				Description: fmt.Sprintf("Compression ratio is %d:1 with uncompressed size %d MB. Unpacking may exhaust disk/memory.", ratio, totalUncompressed/(1024*1024)),
			})
			res.BaseScore += 50
		}
	}

	return nil
}

func inspectTarGz(path string, res *ScanResult) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(strings.ToLower(path), ".gz") || strings.HasSuffix(strings.ToLower(path), ".tgz") {
		gzr, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gzr.Close()
		reader = gzr
	}

	tr := tar.NewReader(reader)
	var dangerousFiles []string

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		entryName := header.Name
		entryExt := strings.ToLower(filepath.Ext(entryName))

		if strings.Contains(entryName, "..") {
			res.Findings = append(res.Findings, Finding{
				Category:    "Archive Security",
				Severity:    SeverityCritical,
				Title:       "Tar Directory Traversal Detected",
				Description: fmt.Sprintf("Tar archive contains path traversal entry: '%s'", entryName),
			})
			res.BaseScore += 60
		}

		if DangerousExtensions[entryExt] {
			dangerousFiles = append(dangerousFiles, fmt.Sprintf("%s (%s)", entryName, entryExt))
		}
	}

	if len(dangerousFiles) > 0 {
		res.Findings = append(res.Findings, Finding{
			Category:    "Archive Security",
			Severity:    SeverityCritical,
			Title:       "Executable Payload Inside Tarball",
			Description: fmt.Sprintf("Archive contains executable files: %s", strings.Join(dangerousFiles, ", ")),
		})
		res.BaseScore += 55
	}

	return nil
}
