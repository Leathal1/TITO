package license

import (
	"crypto/ed25519"
	"encoding/base64"
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

// Embedded Ed25519 public key (base64-encoded).
// This is the ONLY key needed for verification. The private key lives on the license server.
const publicKeyB64 = "CZMtpehuIntYBumoJLb9pFJeWzqf+/GK5b4JSdQnSG4="

// License represents a TITO license
type License struct {
	Key       string    `json:"key"`
	Tier      Tier      `json:"tier"`
	ExpiresAt time.Time `json:"expires_at"`
	OrgName   string    `json:"org_name"`
}

// Global license cache
var cachedLicense *License

// publicKey is the parsed Ed25519 public key, initialized once.
var publicKey ed25519.PublicKey

func init() {
	raw, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		// This should never happen with a valid embedded key
		panic("license: invalid embedded public key: " + err.Error())
	}
	publicKey = ed25519.PublicKey(raw)
}

// ResetCache clears the cached license (for testing)
func ResetCache() {
	cachedLicense = nil
}

// SetPublicKeyForTesting overrides the embedded public key (for test use only).
func SetPublicKeyForTesting(pub ed25519.PublicKey) {
	publicKey = pub
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
		// Handle trial license
		if key == "trial" {
			license, err := checkTrialLicense()
			if err != nil {
				return nil, fmt.Errorf("trial license error: %w", err)
			}
			cachedLicense = license
			return license, nil
		}

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

// ValidateLicenseKey validates a license key and returns the license.
// Key format: tito_{tier}_{orgname}_{expiry}_{ed25519_signature_base64url}
func ValidateLicenseKey(key string) (*License, error) {
	if key == "" {
		return nil, fmt.Errorf("empty license key")
	}

	// Split into at most 5 parts: prefix, tier, orgname, expiry, signature
	// The signature may contain underscores in base64url so we split carefully.
	parts := strings.SplitN(key, "_", 5)
	if len(parts) != 5 || parts[0] != "tito" {
		return nil, fmt.Errorf("invalid license key format")
	}

	tier := Tier(parts[1])
	if tier != TierPro && tier != TierEnterprise {
		return nil, fmt.Errorf("invalid license tier: %s", tier)
	}

	orgName := parts[2]
	expiryStr := parts[3]
	signatureB64 := parts[4]

	// Parse expiry date (YYYYMMDD format)
	expiresAt, err := time.Parse("20060102", expiryStr)
	if err != nil {
		return nil, fmt.Errorf("invalid expiry date: %w", err)
	}

	// The signed payload is everything before the signature
	payload := fmt.Sprintf("tito_%s_%s_%s", tier, orgName, expiryStr)

	// Decode the base64url signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Verify Ed25519 signature
	if !ed25519.Verify(publicKey, []byte(payload), sigBytes) {
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
		if license.Key == "trial-expired" {
			return "TITO Free (trial expired)"
		}
		return "TITO Free"
	}

	// Trial license
	if license.Key == "trial" {
		daysLeft := TrialDaysRemaining()
		if daysLeft >= 0 {
			return fmt.Sprintf("TITO Pro (trial - %d days remaining)", daysLeft)
		}
		return "TITO Pro (trial)"
	}

	info := fmt.Sprintf("TITO %s", strings.ToTitle(string(license.Tier[:1]))+string(license.Tier[1:]))
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

// --- Trial license support ---

// TrialState represents the persisted trial state
type TrialState struct {
	StartedAt time.Time `json:"started_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

const trialDuration = 14 * 24 * time.Hour

// getTrialStatePath returns the path to the trial state file
func getTrialStatePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/tito-trial.json"
	}
	return filepath.Join(homeDir, ".config", "tito", "trial.json")
}

// checkTrialLicense checks or initializes a trial license
func checkTrialLicense() (*License, error) {
	trialPath := getTrialStatePath()

	var state TrialState

	data, err := os.ReadFile(trialPath)
	if err != nil {
		// No trial file — create one
		now := time.Now()
		state = TrialState{
			StartedAt: now,
			ExpiresAt: now.Add(trialDuration),
		}

		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(trialPath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create config directory: %w", err)
		}

		stateJSON, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal trial state: %w", err)
		}
		if err := os.WriteFile(trialPath, stateJSON, 0600); err != nil {
			return nil, fmt.Errorf("failed to write trial state: %w", err)
		}

		fmt.Println("🎉 Trial activated! You have 14 days of TITO Pro features.")
		fmt.Printf("   Trial expires: %s\n", state.ExpiresAt.Format("2006-01-02"))
		fmt.Println()
	} else {
		if err := json.Unmarshal(data, &state); err != nil {
			return nil, fmt.Errorf("failed to parse trial state: %w", err)
		}
	}

	// Check if trial is expired
	if time.Now().After(state.ExpiresAt) {
		fmt.Println("⏰ Trial expired. Falling back to TITO Free.")
		fmt.Println("   Upgrade to Pro to keep premium features: https://tito.security/pricing")
		fmt.Println()
		return &License{
			Key:       "trial-expired",
			Tier:      TierFree,
			ExpiresAt: time.Time{},
			OrgName:   "",
		}, nil
	}

	return &License{
		Key:       "trial",
		Tier:      TierPro,
		ExpiresAt: state.ExpiresAt,
		OrgName:   "Trial",
	}, nil
}

// TrialDaysRemaining returns the number of days remaining in the trial,
// or -1 if no trial is active
func TrialDaysRemaining() int {
	trialPath := getTrialStatePath()
	data, err := os.ReadFile(trialPath)
	if err != nil {
		return -1
	}

	var state TrialState
	if err := json.Unmarshal(data, &state); err != nil {
		return -1
	}

	remaining := time.Until(state.ExpiresAt)
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Hours() / 24)
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
