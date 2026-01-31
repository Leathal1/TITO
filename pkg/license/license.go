package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Tier represents the license tier
type Tier string

const (
	TierFree       Tier = "free"
	TierPro        Tier = "pro"
	TierEnterprise Tier = "enterprise"
)

// License represents a TITO license
type License struct {
	Key       string    `json:"key"`
	Tier      Tier      `json:"tier"`
	ExpiresAt time.Time `json:"expires_at"`
	OrgName   string    `json:"org_name"`
}

// Global license cache
var cachedLicense *License

// ResetCache clears the cached license (for testing)
func ResetCache() {
	cachedLicense = nil
}

// CheckLicense checks for a valid license from env var or config file
func CheckLicense() (*License, error) {
	// Return cached license if available
	if cachedLicense != nil {
		return cachedLicense, nil
	}

	// Check for skip flag (for testing/development)
	if os.Getenv("TITO_SKIP_LICENSE") == "1" {
		cachedLicense = &License{
			Key:       "dev",
			Tier:      TierEnterprise,
			ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
			OrgName:   "Development",
		}
		return cachedLicense, nil
	}

	// 1. Check environment variable
	if key := os.Getenv("TITO_LICENSE_KEY"); key != "" {
		license, err := ValidateLicenseKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid TITO_LICENSE_KEY: %w", err)
		}
		cachedLicense = license
		return license, nil
	}

	// 2. Check config file
	configPath := getLicenseConfigPath()
	if data, err := os.ReadFile(configPath); err == nil {
		var license License
		if err := json.Unmarshal(data, &license); err != nil {
			return nil, fmt.Errorf("failed to parse license config: %w", err)
		}

		// Validate the license from config
		validatedLicense, err := ValidateLicenseKey(license.Key)
		if err != nil {
			return nil, fmt.Errorf("invalid license in config: %w", err)
		}

		cachedLicense = validatedLicense
		return validatedLicense, nil
	}

	// 3. No license found - return free tier
	cachedLicense = &License{
		Key:       "",
		Tier:      TierFree,
		ExpiresAt: time.Time{}, // Never expires for free tier
		OrgName:   "",
	}
	return cachedLicense, nil
}

// IsPro returns true if the license is Pro or Enterprise tier
func IsPro() bool {
	license, err := CheckLicense()
	if err != nil {
		return false
	}

	// Check expiration
	if !license.ExpiresAt.IsZero() && license.ExpiresAt.Before(time.Now()) {
		return false
	}

	return license.Tier == TierPro || license.Tier == TierEnterprise
}

// IsEnterprise returns true if the license is Enterprise tier
func IsEnterprise() bool {
	license, err := CheckLicense()
	if err != nil {
		return false
	}

	// Check expiration
	if !license.ExpiresAt.IsZero() && license.ExpiresAt.Before(time.Now()) {
		return false
	}

	return license.Tier == TierEnterprise
}

// ValidateLicenseKey validates a license key and returns the license
func ValidateLicenseKey(key string) (*License, error) {
	if key == "" {
		return nil, fmt.Errorf("empty license key")
	}

	// Parse the license key format: tito_{tier}_{orgname}_{expiry}_{signature}
	parts := strings.Split(key, "_")
	if len(parts) < 5 || parts[0] != "tito" {
		return nil, fmt.Errorf("invalid license key format")
	}

	tier := Tier(parts[1])
	if tier != TierPro && tier != TierEnterprise {
		return nil, fmt.Errorf("invalid license tier: %s", tier)
	}

	orgName := parts[2]
	expiryStr := parts[3]
	signature := parts[4]

	// Parse expiry date (YYYYMMDD format)
	expiresAt, err := time.Parse("20060102", expiryStr)
	if err != nil {
		return nil, fmt.Errorf("invalid expiry date: %w", err)
	}

	// Verify HMAC signature
	// In production, this secret should be environment-specific
	// For now, we use a simple shared secret
	secret := getSigningSecret()
	payload := fmt.Sprintf("tito_%s_%s_%s", tier, orgName, expiryStr)

	if !verifyHMAC(payload, signature, secret) {
		return nil, fmt.Errorf("invalid license signature")
	}

	// Check if expired
	if expiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("license expired on %s", expiresAt.Format("2006-01-02"))
	}

	return &License{
		Key:       key,
		Tier:      tier,
		ExpiresAt: expiresAt,
		OrgName:   orgName,
	}, nil
}

// GetTier returns the current license tier
func GetTier() Tier {
	license, err := CheckLicense()
	if err != nil {
		return TierFree
	}
	return license.Tier
}

// GetLicenseInfo returns a human-readable license info string
func GetLicenseInfo() string {
	license, err := CheckLicense()
	if err != nil {
		return "TITO Free (unlicensed)"
	}

	if license.Tier == TierFree {
		return "TITO Free"
	}

	info := fmt.Sprintf("TITO %s", strings.Title(string(license.Tier)))
	if license.OrgName != "" {
		info += fmt.Sprintf(" (%s)", license.OrgName)
	}

	if !license.ExpiresAt.IsZero() {
		daysLeft := int(time.Until(license.ExpiresAt).Hours() / 24)
		if daysLeft > 0 {
			info += fmt.Sprintf(" - %d days remaining", daysLeft)
		} else {
			info += " - EXPIRED"
		}
	}

	return info
}

// SaveLicense saves a license to the config file
func SaveLicense(license *License) error {
	configPath := getLicenseConfigPath()

	// Create config directory if it doesn't exist
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal license to JSON
	data, err := json.MarshalIndent(license, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal license: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write license config: %w", err)
	}

	// Clear cache to force reload
	cachedLicense = nil

	return nil
}

// GenerateLicenseKey generates a license key (for internal use / license server)
func GenerateLicenseKey(tier Tier, orgName string, expiresAt time.Time) string {
	expiryStr := expiresAt.Format("20060102")
	payload := fmt.Sprintf("tito_%s_%s_%s", tier, orgName, expiryStr)
	secret := getSigningSecret()
	signature := generateHMAC(payload, secret)

	return fmt.Sprintf("tito_%s_%s_%s_%s", tier, orgName, expiryStr, signature)
}

// Helper functions

func getLicenseConfigPath() string {
	// Check XDG_CONFIG_HOME first
	if configHome := os.Getenv("XDG_CONFIG_HOME"); configHome != "" {
		return filepath.Join(configHome, "tito", "license.json")
	}

	// Fall back to ~/.config/tito/license.json
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/tito-license.json" // Last resort
	}

	return filepath.Join(homeDir, ".config", "tito", "license.json")
}

func getSigningSecret() string {
	// In production, this should be an environment variable or derived from
	// a secure key management system. For now, we use a simple shared secret.
	// This is sufficient for an HMAC check on the client side.
	if secret := os.Getenv("TITO_LICENSE_SECRET"); secret != "" {
		return secret
	}
	return "tito-license-hmac-secret-v1" // Default secret
}

func generateHMAC(message, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))[:16] // Use first 16 chars for brevity
}

func verifyHMAC(message, signature, secret string) bool {
	expectedSignature := generateHMAC(message, secret)
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}
