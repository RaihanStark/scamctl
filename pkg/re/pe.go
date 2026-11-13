package re

import (
	"debug/pe"
	"fmt"
	"math"
	"strings"
	"time"
)

var KnownSuspiciousAPIs = map[string]SuspiciousAPI{
	// Process Injection & Memory
	"virtualalloc":         {Category: "Process Injection / Memory", Description: "Allocates executable memory, frequently used for shellcode staging"},
	"virtualallocex":       {Category: "Process Injection / Memory", Description: "Allocates memory in a remote process (process hollowing/injection)"},
	"writeprocessmemory":   {Category: "Process Injection / Memory", Description: "Writes payload into target process memory space"},
	"createremotethread":   {Category: "Process Injection / Memory", Description: "Executes shellcode thread inside another process"},
	"queueuserapc":         {Category: "Process Injection / Memory", Description: "Queues an asynchronous procedure call (Early Bird APC injection)"},
	"ntunmapviewofsection": {Category: "Process Injection / Memory", Description: "Hollows out legitimate process memory for replacement"},
	"setthreadcontext":     {Category: "Process Injection / Memory", Description: "Hijacks CPU thread execution flow to execute injected code"},

	// Credential Theft & DPAPI
	"cryptunprotectdata": {Category: "Credential Theft", Description: "Decrypts Windows DPAPI secrets (used by Infostealers to steal Chrome/Edge passwords & cookies)"},
	"credenumeratea":     {Category: "Credential Theft", Description: "Enumerates saved Windows credentials and passwords"},
	"credenumeratew":     {Category: "Credential Theft", Description: "Enumerates saved Windows credentials and passwords"},
	"vaultopenvault":     {Category: "Credential Theft", Description: "Opens Windows Credential Vault to harvest stored passwords"},

	// Keylogging & Surveillance
	"setwindowshookexa": {Category: "Spyware / Keylogging", Description: "Installs a global Windows keyboard/mouse hook for keylogging"},
	"setwindowshookexw": {Category: "Spyware / Keylogging", Description: "Installs a global Windows keyboard/mouse hook for keylogging"},
	"getasynckeystate":  {Category: "Spyware / Keylogging", Description: "Monitors keystrokes asynchronously outside active window"},
	"getkeystate":       {Category: "Spyware / Keylogging", Description: "Reads keyboard key states for keylogging"},
	"getclipboarddata":  {Category: "Spyware / Data Theft", Description: "Steals contents of the system clipboard (crypto addresses, passwords)"},

	// Anti-Analysis & Evasion
	"isdebuggerpresent":           {Category: "Anti-Analysis / Evasion", Description: "Detects if application is running under an attached debugger"},
	"checkremotedebuggerpresent":  {Category: "Anti-Analysis / Evasion", Description: "Checks for external debuggers attached to process"},
	"ntqueryinformationprocess":   {Category: "Anti-Analysis / Evasion", Description: "Queries internal process flags (ProcessDebugPort) to detect debuggers"},
	"gettickcount":                {Category: "Anti-Analysis / Evasion", Description: "Measures timing differences to detect virtualization/sandbox delay"},
	"queryperformancecounter":     {Category: "Anti-Analysis / Evasion", Description: "High-resolution timer used for anti-sandbox sleep evasion"},

	// Persistence
	"regsetvalueexa": {Category: "Persistence", Description: "Modifies Windows Registry (e.g. CurrentVersion\\Run for boot persistence)"},
	"regsetvalueexw": {Category: "Persistence", Description: "Modifies Windows Registry (e.g. CurrentVersion\\Run for boot persistence)"},
	"createservicea": {Category: "Persistence", Description: "Registers a persistent Windows background service"},
	"createservicew": {Category: "Persistence", Description: "Registers a persistent Windows background service"},

	// Command Execution
	"shellexecutea": {Category: "Execution", Description: "Launches external programs or scripts"},
	"shellexecutew": {Category: "Execution", Description: "Launches external programs or scripts"},
	"createprocessa": {Category: "Execution", Description: "Spawns new processes"},
	"createprocessw": {Category: "Execution", Description: "Spawns new processes"},
	"winexec":        {Category: "Execution", Description: "Executes command strings directly in shell"},

	// C2 / Networking
	"urldownloadtofilea": {Category: "C2 / Dropper", Description: "Downloads secondary malware payloads directly from a remote URL to disk"},
	"urldownloadtofilew": {Category: "C2 / Dropper", Description: "Downloads secondary malware payloads directly from a remote URL to disk"},
	"internetopena":      {Category: "C2 Communication", Description: "Initializes WinINet session for outbound HTTP/HTTPS C2 traffic"},
	"internetopenw":      {Category: "C2 Communication", Description: "Initializes WinINet session for outbound HTTP/HTTPS C2 traffic"},
	"httpsendrequesta":   {Category: "C2 Communication", Description: "Transmits exfiltrated victim data or receives C2 commands"},
	"httpsendrequestw":   {Category: "C2 Communication", Description: "Transmits exfiltrated victim data or receives C2 commands"},
	"winhttpopen":        {Category: "C2 Communication", Description: "Opens WinHTTP session for stealthy command and control"},
}

// AnalyzePE dissects a Windows Portable Executable
func AnalyzePE(path string, res *REResult) error {
	peFile, err := pe.Open(path)
	if err != nil {
		return err
	}
	defer peFile.Close()

	res.FileType = "Windows PE Binary"

	// 1. Architecture
	switch peFile.FileHeader.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		res.TargetArch = "x86 (32-bit)"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		res.TargetArch = "x64 (64-bit)"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		res.TargetArch = "ARM64"
	default:
		res.TargetArch = fmt.Sprintf("Unknown (0x%x)", peFile.FileHeader.Machine)
	}

	// 2. Compilation Timestamp
	if peFile.FileHeader.TimeDateStamp > 0 {
		t := time.Unix(int64(peFile.FileHeader.TimeDateStamp), 0).UTC()
		res.CompileTimestamp = t.Format("2006-01-02 15:04:05 UTC")
	}

	// 3. Subsystem
	var subsystem uint16
	switch opt := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		subsystem = opt.Subsystem
	case *pe.OptionalHeader64:
		subsystem = opt.Subsystem
	}

	switch subsystem {
	case 2:
		res.Subsystem = "Windows GUI (No console window - stealth)"
	case 3:
		res.Subsystem = "Windows Console (CLI)"
	case 1:
		res.Subsystem = "Native / Driver"
	default:
		res.Subsystem = fmt.Sprintf("Subsystem ID %d", subsystem)
	}

	// 4. Section Analysis & Entropy
	var highEntropySections int
	for _, sec := range peFile.Sections {
		secData, err := sec.Data()
		var entropy float64
		if err == nil && len(secData) > 0 {
			entropy = calculateShannonEntropy(secData)
		}

		cleanName := strings.TrimRight(sec.Name, "\x00")
		isPacked := entropy >= 7.0 || strings.Contains(strings.ToUpper(cleanName), "UPX") || strings.Contains(strings.ToUpper(cleanName), "VMP")

		if isPacked {
			highEntropySections++
			if strings.Contains(strings.ToUpper(cleanName), "UPX") {
				res.PackerHints = append(res.PackerHints, "UPX Packer")
			}
		}

		res.Sections = append(res.Sections, PESection{
			Name:        cleanName,
			VirtualSize: sec.VirtualSize,
			RawSize:     sec.Size,
			Entropy:     math.Round(entropy*100) / 100,
			IsPacked:    isPacked,
		})
	}

	if highEntropySections > 0 {
		res.IsPacked = true
		res.Capabilities = append(res.Capabilities, fmt.Sprintf("Packed / Encrypted: %d high-entropy section(s) detected", highEntropySections))
	}

	// 5. Imports & Suspicious API catalog
	importedSymbols, err := peFile.ImportedSymbols()
	if err == nil {
		for _, sym := range importedSymbols {
			parts := strings.Split(sym, ":")
			var funcName, dllName string
			if len(parts) == 2 {
				dllName = parts[0]
				funcName = parts[1]
			} else {
				funcName = sym
			}

			lowerFunc := strings.ToLower(funcName)
			if susp, ok := KnownSuspiciousAPIs[lowerFunc]; ok {
				susp.Name = funcName
				susp.DLL = dllName
				res.SuspiciousAPIs = append(res.SuspiciousAPIs, susp)
			}
		}
	}

	// Classify capabilities from suspicious APIs
	deriveCapabilitiesFromAPIs(res)

	return nil
}

func calculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	total := float64(len(data))
	var entropy float64

	for _, count := range counts {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func deriveCapabilitiesFromAPIs(res *REResult) {
	categories := make(map[string]bool)
	for _, api := range res.SuspiciousAPIs {
		categories[api.Category] = true
	}

	if categories["Process Injection / Memory"] {
		res.Capabilities = append(res.Capabilities, "Process Injection / Memory Staging (can hollow/inject code into legitimate processes)")
	}
	if categories["Credential Theft"] {
		res.Capabilities = append(res.Capabilities, "Credential Theft via DPAPI (can extract saved browser passwords & tokens)")
	}
	if categories["Spyware / Keylogging"] {
		res.Capabilities = append(res.Capabilities, "Keystroke / Input Interception (Keylogger functionality)")
	}
	if categories["Anti-Analysis / Evasion"] {
		res.Capabilities = append(res.Capabilities, "Anti-Analysis & Debugger Detection (evades sandboxes and analysts)")
	}
	if categories["Persistence"] {
		res.Capabilities = append(res.Capabilities, "Registry / Service Persistence (survives system reboots)")
	}
	if categories["C2 Communication"] || categories["C2 / Dropper"] {
		res.Capabilities = append(res.Capabilities, "Remote C2 Network Staging (downloads payloads or exfiltrates data)")
	}
}
