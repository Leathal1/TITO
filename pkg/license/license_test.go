package license

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func setupTestEnv(t *testing.T) string {
	// Create temp directory for test license files
	tempDir := t.TempDir()
	licenseDir = tempDir
	licensePath = filepath.Join(tempDir, "license.key")
	currentLicense = nil // Clear cache
	publicKey = nil      // Force regeneration
	return tempDir
}

func TestGenerateKeyPair(t *testing.T) {
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	
	if privKey == nil {
		t.Error("Private key is nil")
	}
	
	if pubKey == nil {
		t.Error("Public key is nil")
	}
}

func TestSaveAndLoadKeyPair(t *testing.T) {
	tempDir := setupTestEnv(t)
	keyPath := filepath.Join(tempDir, "test-keypair.pem")
	
	// Generate keypair
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	
	// Save
	if err := SaveKeyPair(privKey, pubKey, keyPath); err != nil {
		t.Fatalf("SaveKeyPair failed: %v", err)
	}
	
	// Load
	loadedPrivKey, loadedPubKey, err := LoadKeyPair(keyPath)
	if err != nil {
		t.Fatalf("LoadKeyPair failed: %v", err)
	}
	
	// Verify keys match
	if loadedPrivKey.N.Cmp(privKey.N) != 0 {
		t.Error("Private keys don't match")
	}
	
	if loadedPubKey.N.Cmp(pubKey.N) != 0 {
		t.Error("Public keys don't match")
	}
}

func TestGenerateLicenseKey(t *testing.T) {
	privKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	
	opts := LicenseKeyOptions{
		Tier:      TierPro,
		Features:  []string{"drift-detection", "llm-intelligence"},
		User:      "test@example.com",
		ValidDays: 365,
		IsTrial:   false,
	}
	
	key, err := GenerateLicenseKey(privKey, opts)
	if err != nil {
		t.Fatalf("GenerateLicenseKey failed: %v", err)
	}
	
	if key == "" {
		t.Error("Generated key is empty")
	}
}

func TestValidateLicense(t *testing.T) {
	setupTestEnv(t)
	
	// Initialize system (generates test keypair)
	if err := InitLicenseSystem(); err != nil {
		t.Fatalf("InitLicenseSystem failed: %v", err)
	}
	
	// Load keypair for signing
	keyPairPath := filepath.Join(licenseDir, "test-keypair.pem")
	privKey, _, err := LoadKeyPair(keyPairPath)
	if err != nil {
		t.Fatalf("LoadKeyPair failed: %v", err)
	}
	
	// Generate a license
	opts := LicenseKeyOptions{
		Tier:      TierPro,
		Features:  []string{"drift-detection"},
		User:      "test@example.com",
		ValidDays: 30,
		IsTrial:   false,
	}
	
	key, err := GenerateLicenseKey(privKey, opts)
	if err != nil {
		t.Fatalf("GenerateLicenseKey failed: %v", err)
	}
	
	// Validate
	license, err := ValidateLicense(key)
	if err != nil {
		t.Fatalf("ValidateLicense failed: %v", err)
	}
	
	if license.Tier != TierPro {
		t.Errorf("Expected tier %s, got %s", TierPro, license.Tier)
	}
	
	if license.User != "test@example.com" {
		t.Errorf("Expected user test@example.com, got %s", license.User)
	}
	
	if len(license.Features) != 1 || license.Features[0] != "drift-detection" {
		t.Errorf("Features mismatch: %v", license.Features)
	}
}

func TestExpiredLicense(t *testing.T) {
	setupTestEnv(t)
	
	// Initialize system
	if err := InitLicenseSystem(); err != nil {
		t.Fatalf("InitLicenseSystem failed: %v", err)
	}
	
	// Load keypair
	keyPairPath := filepath.Join(licenseDir, "test-keypair.pem")
	privKey, _, err := LoadKeyPair(keyPairPath)
	if err != nil {
		t.Fatalf("LoadKeyPair failed: %v", err)
	}
	
	// Generate expired license (manually set expiry to 10 days ago)
	now := time.Now()
	expiredTime := now.Add(-10 * 24 * time.Hour)
	
	claims := Claims{
		Tier:     string(TierPro),
		Features: []string{"drift-detection"},
		User:     "test@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now.Add(-15 * 24 * time.Hour)), // Issued 15 days ago
			ExpiresAt: jwt.NewNumericDate(expiredTime), // Expired 10 days ago
			Subject:   "test@example.com",
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	key, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("GenerateLicenseKey failed: %v", err)
	}
	
	// This should fail validation (outside grace period)
	_, err = ValidateLicense(key)
	if err == nil {
		t.Error("Expected validation to fail for expired license outside grace period")
	}
}

func TestTrialLicense(t *testing.T) {
	setupTestEnv(t)
	
	// Initialize system
	if err := InitLicenseSystem(); err != nil {
		t.Fatalf("InitLicenseSystem failed: %v", err)
	}
	
	// Generate trial license
	key, err := GenerateTrialLicense("trial@example.com")
	if err != nil {
		t.Fatalf("GenerateTrialLicense failed: %v", err)
	}
	
	// Validate
	license, err := ValidateLicense(key)
	if err != nil {
		t.Fatalf("ValidateLicense failed: %v", err)
	}
	
	if !license.IsTrial {
		t.Error("Expected trial license")
	}
	
	if license.Tier != TierPro {
		t.Errorf("Expected Pro tier for trial, got %s", license.Tier)
	}
	
	// Check expiration is ~14 days from now
	expectedExpiry := time.Now().Add(14 * 24 * time.Hour)
	diff := license.ExpiresAt.Sub(expectedExpiry).Abs()
	if diff > time.Minute {
		t.Errorf("Trial expiry not ~14 days: %v", license.ExpiresAt)
	}
}

func TestSaveAndLoadLicense(t *testing.T) {
	setupTestEnv(t)
	
	// Initialize system
	if err := InitLicenseSystem(); err != nil {
		t.Fatalf("InitLicenseSystem failed: %v", err)
	}
	
	// Generate trial
	key, err := GenerateTrialLicense("test@example.com")
	if err != nil {
		t.Fatalf("GenerateTrialLicense failed: %v", err)
	}
	
	// Save
	if err := SaveLicense(key); err != nil {
		t.Fatalf("SaveLicense failed: %v", err)
	}
	
	// Load
	license, err := GetCurrentLicense()
	if err != nil {
		t.Fatalf("GetCurrentLicense failed: %v", err)
	}
	
	if license.Tier != TierPro {
		t.Errorf("Expected Pro tier, got %s", license.Tier)
	}
	
	if !license.IsTrial {
		t.Error("Expected trial license")
	}
}

func TestGetCurrentLicenseNoFile(t *testing.T) {
	setupTestEnv(t)
	
	// Initialize system
	if err := InitLicenseSystem(); err != nil {
		t.Fatalf("InitLicenseSystem failed: %v", err)
	}
	
	// No license file should return Community tier
	license, err := GetCurrentLicense()
	if err != nil {
		t.Fatalf("GetCurrentLicense failed: %v", err)
	}
	
	if license.Tier != TierCommunity {
		t.Errorf("Expected Community tier when no license file, got %s", license.Tier)
	}
}

func TestIsProEnabled(t *testing.T) {
	setupTestEnv(t)
	
	// Initialize system
	if err := InitLicenseSystem(); err != nil {
		t.Fatalf("InitLicenseSystem failed: %v", err)
	}
	
	// Initially Community (no license file)
	if IsProEnabled() {
		t.Error("Pro should not be enabled with no license")
	}
	
	// Activate trial
	key, err := GenerateTrialLicense("test@example.com")
	if err != nil {
		t.Fatalf("GenerateTrialLicense failed: %v", err)
	}
	
	if err := SaveLicense(key); err != nil {
		t.Fatalf("SaveLicense failed: %v", err)
	}
	
	// Now Pro should be enabled
	currentLicense = nil // Clear cache
	if !IsProEnabled() {
		t.Error("Pro should be enabled after trial activation")
	}
}

func TestIsFeatureEnabled(t *testing.T) {
	setupTestEnv(t)
	
	// Initialize system
	if err := InitLicenseSystem(); err != nil {
		t.Fatalf("InitLicenseSystem failed: %v", err)
	}
	
	// Load keypair
	keyPairPath := filepath.Join(licenseDir, "test-keypair.pem")
	privKey, _, err := LoadKeyPair(keyPairPath)
	if err != nil {
		t.Fatalf("LoadKeyPair failed: %v", err)
	}
	
	// Generate license with specific features
	opts := LicenseKeyOptions{
		Tier:      TierPro,
		Features:  []string{"drift-detection", "llm-intelligence"},
		User:      "test@example.com",
		ValidDays: 30,
	}
	
	key, err := GenerateLicenseKey(privKey, opts)
	if err != nil {
		t.Fatalf("GenerateLicenseKey failed: %v", err)
	}
	
	if err := SaveLicense(key); err != nil {
		t.Fatalf("SaveLicense failed: %v", err)
	}
	
	currentLicense = nil // Clear cache
	
	// Test feature checks
	if !IsFeatureEnabled("drift-detection") {
		t.Error("drift-detection should be enabled")
	}
	
	if !IsFeatureEnabled("llm-intelligence") {
		t.Error("llm-intelligence should be enabled")
	}
	
	if IsFeatureEnabled("nonexistent-feature") {
		t.Error("nonexistent-feature should not be enabled")
	}
}

func TestEncodeDecode(t *testing.T) {
	originalKey := "test-license-key-12345"
	
	encoded := EncodeLicenseKey(originalKey)
	decoded, err := DecodeLicenseKey(encoded)
	
	if err != nil {
		t.Fatalf("DecodeLicenseKey failed: %v", err)
	}
	
	if decoded != originalKey {
		t.Errorf("Decoded key doesn't match original: %s != %s", decoded, originalKey)
	}
}

func TestCommunityByDefault(t *testing.T) {
	setupTestEnv(t)
	
	// Don't create any license file
	// Community tier should be active by default
	license, err := GetCurrentLicense()
	if err != nil {
		t.Fatalf("GetCurrentLicense failed: %v", err)
	}
	
	if license.Tier != TierCommunity {
		t.Errorf("Expected Community tier by default, got %s", license.Tier)
	}
	
	if IsProEnabled() {
		t.Error("Pro should not be enabled by default")
	}
}

// Cleanup
func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
