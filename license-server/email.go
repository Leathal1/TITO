package main

import (
	"fmt"
	"log"
	"net/smtp"
	"os"
	"strings"
)

// sendLicenseEmail sends the license key to the buyer
// For now, this just logs the key. To enable SMTP, set these env vars:
//   SMTP_HOST=smtp.gmail.com
//   SMTP_PORT=587
//   SMTP_USER=your-email@gmail.com
//   SMTP_PASSWORD=your-app-password
//   SMTP_FROM=noreply@tito.security
func sendLicenseEmail(to, licenseKey, tier string) error {
	subject := fmt.Sprintf("Your TITO %s License Key", strings.ToTitle(string(tier[:1]))+string(tier[1:]))
	
	body := fmt.Sprintf(`Thank you for purchasing TITO %s!

Your license key:

%s

To activate, run:

    tito activate %s

Or set the environment variable:

    export TITO_LICENSE_KEY="%s"

Your license includes:
• Drift detection
• 3D visualization
• Full attack paths
• Scan result saving
• PR diff reports
%s

Support: support@tito.security
Documentation: https://tito.security/docs

-- 
TITO Team
https://tito.security
`, strings.ToTitle(string(tier[:1]))+string(tier[1:]), 
   licenseKey, licenseKey, licenseKey, getFeatureList(tier))

	// Check if SMTP is configured
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASSWORD")
	smtpFrom := os.Getenv("SMTP_FROM")

	if smtpHost == "" || smtpPort == "" {
		// SMTP not configured - just log
		log.Printf("===== LICENSE EMAIL =====")
		log.Printf("To: %s", to)
		log.Printf("Subject: %s", subject)
		log.Printf("Body:\n%s", body)
		log.Printf("=========================")
		return nil
	}

	// Send via SMTP
	if smtpFrom == "" {
		smtpFrom = "noreply@tito.security"
	}

	msg := []byte(fmt.Sprintf("To: %s\r\n"+
		"From: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", to, smtpFrom, subject, body))

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)

	err := smtp.SendMail(addr, auth, smtpFrom, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("SMTP send failed: %w", err)
	}

	log.Printf("✓ License email sent to %s", to)
	return nil
}

func getFeatureList(tier string) string {
	switch tier {
	case "team":
		return `• Multi-repo scanning
• Custom threat libraries
• Workshop mode`
	case "enterprise":
		return `• Multi-repo scanning
• Custom threat libraries
• Workshop mode
• Attack simulation
• Compliance mapping
• API access
• SSO/SAML
• Priority support`
	default:
		return ""
	}
}
