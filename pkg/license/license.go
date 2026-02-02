package license

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Tier represents the license tier level
type Tier string

const (
	TierCommunity  Tier = "community"
	TierPro        Tier = "pro"
	TierTeam       Tier = "team"
	TierEnterprise Tier = "enterprise"
)

// License represents a TITO license
type License struct {
	Key       string    `json:"key"`
	Tier      Tier      `json:"tier"`
	ExpiresAt time.Time `json:"expiresAt"`
	Features  []string  `json:"features"`
	User      string    `json:"user,omitempty"`
	OrgID     string    `json:"orgId,omitempty"`
	IssuedAt  time.Time `json:"issuedAt"`
	IsTrial   bool      `json:"isTrial"`
}

// Claims represents JWT claims for license validation
type Claims struct {
	Tier      string   `json:"tier"`
	Features  []string `json:"features"`
	User      string   `json:"user,omitempty"`
	OrgID     string   `json:"orgId,omitempty"`
	IsTrial   bool     `json:"trial,omitempty"`
	jwt.RegisteredClaims
}

var (
	// Global current license (loaded on first check)
	currentLicense *License
	
	// Embedded public key for offline validation (PEM format)
	// In production, this would be embedded at build time
	// For now, we'll generate a keypair for testing
	publicKey *rsa.PublicKey
	
	// License file path
	licenseDir  = filepath.Join(os.Getenv("HOME"), ".tito")
	licensePath = filepath.Join(licenseDir, "license.key")
	
	// Grace period for offline validation (7 days)
	offlineGraceDays = 7
)

// InitLicenseSystem initializes the license validation system
func InitLicenseSystem() error {
	// Ensure license directory exists
	if err := os.MkdirAll(licenseDir, 0755); err != nil {
		return fmt.Errorf("failed to create license directory: %w", err)
	}
	
	// In production, publicKey would be embedded in the binary
	// For testing, we'll load or generate a keypair
	if publicKey == nil {
		keyPairPath := filepath.Join(licenseDir, "test-keypair.pem")
		if _, err := os.Stat(keyPairPath); os.IsNotExist(err) {
			// Generate test keypair
			privKey, pubKey, err := GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("failed to generate test keypair: %w", err)
			}
			publicKey = pubKey
			
			// Save private key for testing (server-side key generation)
			if err := SaveKeyPair(privKey, pubKey, keyPairPath); err != nil {
				return fmt.Errorf("failed to save test keypair: %w", err)
			}
		} else {
			// Load existing keypair
			_, pubKey, err := LoadKeyPair(keyPairPath)
			if err != nil {
				return fmt.Errorf("failed to load test keypair: %w", err)
			}
			publicKey = pubKey
		}
	}
	
	return nil
}

// ValidateLicense validates a license key and returns the license details
func ValidateLicense(key string) (*License, error) {
	if key == "" {
		return nil, fmt.Errorf("empty license key")
	}
	
	// Ensure license system is initialized
	if err := InitLicenseSystem(); err != nil {
		return nil, err
	}
	
	// Parse JWT token
	token, err := jwt.ParseWithClaims(key, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("invalid license key: %w", err)
	}
	
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid license claims")
	}
	
	// Check expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		// Check if within offline grace period
		gracePeriod := time.Now().Add(-time.Duration(offlineGraceDays) * 24 * time.Hour)
		if claims.ExpiresAt.Time.Before(gracePeriod) {
			return nil, fmt.Errorf("license expired on %s", claims.ExpiresAt.Time.Format("2006-01-02"))
		}
		// Within grace period - allow but warn
		fmt.Fprintf(os.Stderr, "Warning: License expired on %s (grace period active)\n", 
			claims.ExpiresAt.Time.Format("2006-01-02"))
	}
	
	// Build license object
	license := &License{
		Key:       key,
		Tier:      Tier(claims.Tier),
		Features:  claims.Features,
		User:      claims.User,
		OrgID:     claims.OrgID,
		IsTrial:   claims.IsTrial,
		IssuedAt:  claims.IssuedAt.Time,
	}
	
	if claims.ExpiresAt != nil {
		license.ExpiresAt = claims.ExpiresAt.Time
	}
	
	return license, nil
}

// GetCurrentLicense reads and validates the current license from ~/.tito/license.key
func GetCurrentLicense() (*License, error) {
	// Return cached license if available
	if currentLicense != nil {
		// Re-validate to check expiration
		validated, err := ValidateLicense(currentLicense.Key)
		if err != nil {
			// License became invalid - clear cache
			currentLicense = nil
			return nil, err
		}
		return validated, nil
	}
	
	// Ensure license system is initialized
	if err := InitLicenseSystem(); err != nil {
		return nil, err
	}
	
	// Check if license file exists
	if _, err := os.Stat(licensePath); os.IsNotExist(err) {
		// No license file - return Community tier
		return &License{
			Tier:     TierCommunity,
			Features: []string{},
		}, nil
	}
	
	// Read license key from file
	keyBytes, err := os.ReadFile(licensePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file: %w", err)
	}
	
	key := string(keyBytes)
	
	// Validate and cache
	license, err := ValidateLicense(key)
	if err != nil {
		return nil, err
	}
	
	currentLicense = license
	return license, nil
}

// SaveLicense saves a license key to ~/.tito/license.key
func SaveLicense(key string) error {
	// Validate first
	_, err := ValidateLicense(key)
	if err != nil {
		return fmt.Errorf("cannot save invalid license: %w", err)
	}
	
	// Ensure directory exists
	if err := os.MkdirAll(licenseDir, 0755); err != nil {
		return fmt.Errorf("failed to create license directory: %w", err)
	}
	
	// Write license key
	if err := os.WriteFile(licensePath, []byte(key), 0600); err != nil {
		return fmt.Errorf("failed to write license file: %w", err)
	}
	
	// Clear cache to force reload
	currentLicense = nil
	
	return nil
}

// GenerateTrialLicense generates a 14-day Pro trial license
func GenerateTrialLicense(user string) (string, error) {
	// Ensure license system is initialized
	if err := InitLicenseSystem(); err != nil {
		return "", err
	}
	
	// Load private key for signing (testing only - production would be server-side)
	keyPairPath := filepath.Join(licenseDir, "test-keypair.pem")
	privateKey, _, err := LoadKeyPair(keyPairPath)
	if err != nil {
		return "", fmt.Errorf("failed to load signing key: %w", err)
	}
	
	now := time.Now()
	expiresAt := now.Add(14 * 24 * time.Hour)
	
	claims := Claims{
		Tier:     string(TierPro),
		Features: []string{"drift-detection", "llm-intelligence", "exploitability-scoring"},
		User:     user,
		IsTrial:  true,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Subject:   user,
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	licenseKey, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign license: %w", err)
	}
	
	return licenseKey, nil
}

// IsProEnabled checks if the current license is Pro tier or higher
func IsProEnabled() bool {
	license, err := GetCurrentLicense()
	if err != nil {
		return false
	}
	
	return license.Tier == TierPro || 
	       license.Tier == TierTeam || 
	       license.Tier == TierEnterprise
}

// IsTeamEnabled checks if the current license is Team tier or higher
func IsTeamEnabled() bool {
	license, err := GetCurrentLicense()
	if err != nil {
		return false
	}
	
	return license.Tier == TierTeam || 
	       license.Tier == TierEnterprise
}

// IsEnterpriseEnabled checks if the current license is Enterprise tier
func IsEnterpriseEnabled() bool {
	license, err := GetCurrentLicense()
	if err != nil {
		return false
	}
	
	return license.Tier == TierEnterprise
}

// IsFeatureEnabled checks if a specific feature is enabled
func IsFeatureEnabled(feature string) bool {
	license, err := GetCurrentLicense()
	if err != nil {
		return false
	}
	
	for _, f := range license.Features {
		if f == feature {
			return true
		}
	}
	
	return false
}

// RequireProOrUpgrade checks if Pro is enabled, otherwise prints upgrade message and returns false
func RequireProOrUpgrade(featureName string) bool {
	if IsProEnabled() {
		return true
	}
	
	fmt.Println()
	fmt.Printf("⭐ %s is a TITO Pro feature\n", featureName)
	fmt.Println()
	fmt.Println("Upgrade to Pro for:")
	fmt.Println("  • LLM-powered threat intelligence")
	fmt.Println("  • Exploitability prediction")
	fmt.Println("  • Continuous drift detection")
	fmt.Println("  • Auto-remediation advisor")
	fmt.Println()
	fmt.Println("Learn more: https://tito.security/pro")
	fmt.Println()
	fmt.Println("Try it free:")
	fmt.Println("  tito activate --trial    # 14-day Pro trial, no credit card")
	fmt.Println()
	
	return false
}

// PrintLicenseStatus prints the current license status in a user-friendly format
func PrintLicenseStatus() error {
	license, err := GetCurrentLicense()
	if err != nil {
		return err
	}
	
	fmt.Println("📄 TITO License Status")
	fmt.Println("═════════════════════════════════════════")
	fmt.Println()
	
	// Tier
	tierEmoji := map[Tier]string{
		TierCommunity:  "🆓",
		TierPro:        "⭐",
		TierTeam:       "👥",
		TierEnterprise: "🏢",
	}
	
	emoji := tierEmoji[license.Tier]
	fmt.Printf("Tier:         %s %s", emoji, license.Tier)
	if license.IsTrial {
		fmt.Print(" (Trial)")
	}
	fmt.Println()
	
	// User
	if license.User != "" {
		fmt.Printf("User:         %s\n", license.User)
	}
	
	// Organization
	if license.OrgID != "" {
		fmt.Printf("Organization: %s\n", license.OrgID)
	}
	
	// Expiration
	if !license.ExpiresAt.IsZero() {
		daysRemaining := int(time.Until(license.ExpiresAt).Hours() / 24)
		status := "Active"
		if daysRemaining < 0 {
			status = "Expired"
		} else if daysRemaining <= 7 {
			status = "Expiring soon"
		}
		
		fmt.Printf("Expires:      %s (%d days, %s)\n", 
			license.ExpiresAt.Format("2006-01-02"), 
			daysRemaining, 
			status)
	}
	
	// Features
	if len(license.Features) > 0 {
		fmt.Println()
		fmt.Println("Enabled Features:")
		for _, feature := range license.Features {
			fmt.Printf("  ✓ %s\n", feature)
		}
	}
	
	// Upgrade path
	if license.Tier == TierCommunity {
		fmt.Println()
		fmt.Println("🚀 Upgrade to Pro:")
		fmt.Println("   tito activate --trial           # Start 14-day free trial")
		fmt.Println("   https://tito.security/pro       # Purchase license")
	}
	
	fmt.Println()
	
	return nil
}

// EncodeLicenseKey encodes a license key to base64 for easier copying
func EncodeLicenseKey(key string) string {
	return base64.StdEncoding.EncodeToString([]byte(key))
}

// DecodeLicenseKey decodes a base64-encoded license key
func DecodeLicenseKey(encodedKey string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		// Try as raw key
		return encodedKey, nil
	}
	return string(decoded), nil
}

// MarshalLicense marshals a license to JSON for storage/transmission
func MarshalLicense(license *License) ([]byte, error) {
	return json.MarshalIndent(license, "", "  ")
}

// UnmarshalLicense unmarshals a license from JSON
func UnmarshalLicense(data []byte) (*License, error) {
	var license License
	if err := json.Unmarshal(data, &license); err != nil {
		return nil, err
	}
	return &license, nil
}
