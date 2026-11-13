package ai

import (
	"fmt"
	"strings"
)

const jsonSchemaInstruction = `
Respond with ONLY valid JSON with this exact schema (no markdown, no extra commentary):
{
  "risk_score": <number between 0 and 100>,
  "verdict": "<SAFE|SUSPICIOUS|HIGH_RISK|MALICIOUS>",
  "confidence": "<LOW|MEDIUM|HIGH>",
  "tactics": ["<list of scam/deception tactics identified>"],
  "red_flags": ["<specific suspicious quotes or signals found in text>"],
  "summary": "<1-2 sentence concise executive explanation>",
  "recommendation": "<direct actionable safety advice for the user>"
}
`

func BuildTextPrompt(text string) string {
	return fmt.Sprintf(`You are an elite cybersecurity and scam detection expert analyzing a suspicious message, email, proposal, or communication.

ANALYZE FOR THE FOLLOWING THREAT PATTERNS:
1. Urgency / Panic / Threatening tone (e.g., immediate account suspension, legal action, 24-hour deadline).
2. Authority Impersonation (e.g., Geek Squad, Norton, PayPal, Bank, Upwork Support, IRS/Tax, CEO/Executive).
3. Financial / Crypto Lures (e.g., fake check deposits, equipment reimbursements, overpayment refund, investment yields, crypto wallet validation / seed phrase requests).
4. Off-Platform Diversion (e.g., forcing conversation to Telegram, WhatsApp, Signal, Skype before an official contract/payment is established).
5. Technical Lures (e.g., asking user to run a command in terminal/PowerShell, test an unknown script, disable antivirus, or open suspicious links).
6. Credential Harvesting / Phishing (e.g., fake login portals, Google Forms requesting ID documents or credit cards).

INPUT CONTENT TO ANALYZE:
"""
%s
"""

%s`, text, jsonSchemaInstruction)
}

func BuildAttachmentPrompt(fileName, mime string, staticFindings []string, extractedText, userContext string) string {
	findingsStr := "None"
	if len(staticFindings) > 0 {
		findingsStr = strings.Join(staticFindings, "\n- ")
	}

	return fmt.Sprintf(`You are an elite cybersecurity malware and social engineering analyst assessing a file attachment.

FILE METADATA:
- File Name: %s
- Detected Type: %s
- Static Security Flags:
- %s

USER CONTEXT / MESSAGE:
%s

EXTRACTED TEXT / STRINGS FROM FILE:
"""
%s
"""

EVALUATE:
1. Is there an intent to deceive the recipient into executing malware or bypassing security?
2. Does the message claim the file is one thing (e.g. invoice, resume, project brief) while the technical attributes suggest another?
3. Are there social engineering prompts asking the user to "Enable Editing", "Enable Content/Macros", or copy-paste commands into a terminal?

%s`, fileName, mime, findingsStr, userContext, extractedText, jsonSchemaInstruction)
}
