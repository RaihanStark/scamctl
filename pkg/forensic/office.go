package forensic

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// Relationships XML structure for OpenXML
type Relationships struct {
	XMLName  xml.Name       `xml:"Relationships"`
	Relation []Relationship `xml:"Relationship"`
}

type Relationship struct {
	Id         string `xml:"Id,attr"`
	Type       string `xml:"Type,attr"`
	Target     string `xml:"Target,attr"`
	TargetMode string `xml:"TargetMode,attr"`
}

// InspectOfficeDocument inspects docx, xlsx, pptx, docm, xlsm OpenXML files
func InspectOfficeDocument(path string, res *ScanResult) error {
	ext := strings.ToLower(filepath.Ext(path))
	officeExts := map[string]bool{
		".docx": true, ".docm": true, ".dotm": true,
		".xlsx": true, ".xlsm": true, ".xltm": true,
		".pptx": true, ".pptm": true, ".potm": true,
	}

	if !officeExts[ext] {
		return nil
	}

	r, err := zip.OpenReader(path)
	if err != nil {
		// Not a valid zip or old OLE binary format
		return nil
	}
	defer r.Close()

	var hasVBAMacro bool
	var externalTemplates []string

	for _, f := range r.File {
		name := strings.ToLower(f.Name)

		// 1. Detect VBA project binaries
		if strings.HasSuffix(name, "vbaproject.bin") {
			hasVBAMacro = true
		}

		// 2. Detect Remote Template Injection in .rels files
		if strings.HasSuffix(name, ".rels") {
			rc, err := f.Open()
			if err == nil {
				data, _ := io.ReadAll(rc)
				rc.Close()

				var rels Relationships
				if err := xml.Unmarshal(data, &rels); err == nil {
					for _, rel := range rels.Relation {
						if rel.TargetMode == "External" {
							if strings.Contains(rel.Type, "attachedTemplate") ||
								strings.Contains(strings.ToLower(rel.Target), ".dotm") ||
								strings.Contains(strings.ToLower(rel.Target), "http") {
								externalTemplates = append(externalTemplates, rel.Target)
							}
						}
					}
				}
			}
		}
	}

	if hasVBAMacro {
		res.Findings = append(res.Findings, Finding{
			Category:    "Office Macro Threat",
			Severity:    SeverityCritical,
			Title:       "VBA Macro Code Detected",
			Description: "Document contains embedded VBA executable macro code (vbaProject.bin). Attackers use macros to download and install infostealers or ransomware.",
		})
		res.BaseScore += 50
	}

	if len(externalTemplates) > 0 {
		res.Findings = append(res.Findings, Finding{
			Category:    "Office Exploit",
			Severity:    SeverityCritical,
			Title:       "Remote Template Injection Detected",
			Description: fmt.Sprintf("Document references external remote template(s): %s. When opened, it connects to remote server to fetch code.", strings.Join(externalTemplates, ", ")),
		})
		res.BaseScore += 60
	}

	return nil
}
