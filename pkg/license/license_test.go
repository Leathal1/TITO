package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"
)

// testPrivateKey is an Ed25519 private key used only in tests.
var testPrivateKey ed25519.PrivateKey
var testPublicKey ed25519.PublicKey

func TestMain(m *testing.M) {
	// Generate a throwaway keypair for tests
	var err error
	testPublicKey, testPrivateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate test keypair: %v\n", err)
		os.Exit(1)
	}

	// Override the embedded public key with our test key
	SetPublicKeyForTesting(testPublicKey)

	os.Exit(m.Run())
}

// generateTestKey signs a license key using the test private key.
func generateTestKey(tier Tier, orgName string, expiresAt time.Time) string {
	expiryStr := expiresAt.Format("20060102")
	payload := fmt.Sprintf("tito_%s_%s_%s", tier, orgName, expiryStr)
	sig := ed25519.Sign(testPrivateKey, []byte(payload))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return fmt.Sprintf("tito_%s_%s_%s_%s", tier, orgName, expiryStr, sigB64)
}

func TestValidateLicenseKey(t *testing.T) {
	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	key := generateTestKey(TierPro, "TestOrg", expiresAt)

	license, err := ValidateLicenseKey(key)
	if err != nil {
		t.Fatalf("ValidateLicenseKey failed: %v", err)
	}

	if license.Tier != TierPro {
		t.Errorf("Expected tier %s, got %s", TierPro, license.Tier)
	}

	if license.OrgName != "TestOrg" {
		t.Errorf("Expected org name TestOrg, got %s", license.OrgName)
	}
}

func TestValidateLicenseKey_AllTiers(t *testing.T) {
	tiers := []Tier{TierCommunity, TierPro, TierTeam, TierEnterprise}
	expiresAt := time.Now().Add(365 * 24 * time.Hour)

	for _, tier := range tiers {
		t.Run(string(tier), func(t *testing.T) {
			key := generateTestKey(tier, "TestOrg", expiresAt)
			license, err := ValidateLicenseKey(key)
			if err != nil {
				t.Fatalf("ValidateLicenseKey failed for %s: %v", tier, err)
			}

			if license.Tier != tier {
				t.Errorf("Expected tier %s, got %s", tier, license.Tier)
			}
		})
	}
}

func TestValidateLicenseKey_Expired(t *testing.T) {
	expiresAt := time.Now().Add(-24 * time.Hour)
	key := generateTestKey(TierPro, "TestOrg", expiresAt)

	_, err := ValidateLicenseKey(key)
	if err == nil {
		t.Fatal("Expected error for expired license, got nil")
	}
}

func TestValidateLicenseKey_InvalidFormat(t *testing.T) {
	_, err := ValidateLicenseKey("invalid_key")
	if err == nil {
		t.Fatal("Expected error for invalid key format, got nil")
	}
}

func TestValidateLicenseKey_TamperedSignature(t *testing.T) {
	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	key := generateTestKey(TierPro, "TestOrg", expiresAt)

	// Tamper with the signature (flip some bits in the middle of signature)
	parts := key[:len(key)-20] + "XXXXXXXXXX" + key[len(key)-10:]
	_, err := ValidateLicenseKey(parts)
	if err == nil {
		t.Fatal("Expected error for tampered signature, got nil")
	}
}

func TestValidateLicenseKey_WrongKey(t *testing.T) {
	// Sign with a completely different private key
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	expiryStr := expiresAt.Format("20060102")
	payload := fmt.Sprintf("tito_%s_%s_%s", TierPro, "TestOrg", expiryStr)
	sig := ed25519.Sign(otherPriv, []byte(payload))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	key := fmt.Sprintf("tito_%s_%s_%s_%s", TierPro, "TestOrg", expiryStr, sigB64)

	_, err := ValidateLicenseKey(key)
	if err == nil {
		t.Fatal("Expected error for key signed with wrong private key, got nil")
	}
}

func TestCheckLicense_SkipFlag(t *testing.T) {
	os.Setenv("TITO_SKIP_LICENSE", "1")
	defer os.Unsetenv("TITO_SKIP_LICENSE")

	cachedLicense = nil

	license, err := CheckLicense()
	if err != nil {
		t.Fatalf("CheckLicense failed: %v", err)
	}

	if license.Tier != TierEnterprise {
		t.Errorf("Expected enterprise tier with skip flag, got %s", license.Tier)
	}
}

func TestCheckLicense_EnvVar(t *testing.T) {
	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	key := generateTestKey(TierPro, "EnvTest", expiresAt)

	os.Setenv("TITO_LICENSE_KEY", key)
	defer os.Unsetenv("TITO_LICENSE_KEY")

	cachedLicense = nil
	os.Unsetenv("TITO_SKIP_LICENSE")

	license, err := CheckLicense()
	if err != nil {
		t.Fatalf("CheckLicense failed: %v", err)
	}

	if license.OrgName != "EnvTest" {
		t.Errorf("Expected org name EnvTest, got %s", license.OrgName)
	}
}

func TestCheckLicense_Community(t *testing.T) {
	os.Unsetenv("TITO_LICENSE_KEY")
	os.Unsetenv("TITO_SKIP_LICENSE")
	cachedLicense = nil

	license, err := CheckLicense()
	if err != nil {
		t.Fatalf("CheckLicense failed: %v", err)
	}

	if license.Tier != TierCommunity {
		t.Errorf("Expected community tier, got %s", license.Tier)
	}
}

func TestIsPro(t *testing.T) {
	tests := []struct {
		name     string
		tier     Tier
		expected bool
	}{
		{"Community tier", TierCommunity, false},
		{"Pro tier", TierPro, true},
		{"Team tier", TierTeam, true},
		{"Enterprise tier", TierEnterprise, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tier == TierCommunity {
				os.Unsetenv("TITO_LICENSE_KEY")
				os.Unsetenv("TITO_SKIP_LICENSE")
			} else {
				expiresAt := time.Now().Add(365 * 24 * time.Hour)
				key := generateTestKey(tt.tier, "TestOrg", expiresAt)
				os.Setenv("TITO_LICENSE_KEY", key)
				defer os.Unsetenv("TITO_LICENSE_KEY")
			}

			cachedLicense = nil
			result := IsPro()

			if result != tt.expected {
				t.Errorf("IsPro() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsTeam(t *testing.T) {
	tests := []struct {
		name     string
		tier     Tier
		expected bool
	}{
		{"Community tier", TierCommunity, false},
		{"Pro tier", TierPro, false},
		{"Team tier", TierTeam, true},
		{"Enterprise tier", TierEnterprise, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tier == TierCommunity {
				os.Unsetenv("TITO_LICENSE_KEY")
				os.Unsetenv("TITO_SKIP_LICENSE")
			} else {
				expiresAt := time.Now().Add(365 * 24 * time.Hour)
				key := generateTestKey(tt.tier, "TestOrg", expiresAt)
				os.Setenv("TITO_LICENSE_KEY", key)
				defer os.Unsetenv("TITO_LICENSE_KEY")
			}

			cachedLicense = nil
			result := IsTeam()

			if result != tt.expected {
				t.Errorf("IsTeam() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsEnterprise(t *testing.T) {
	expiresAt := time.Now().Add(365 * 24 * time.Hour)

	// Test Enterprise tier
	key := generateTestKey(TierEnterprise, "TestOrg", expiresAt)
	os.Setenv("TITO_LICENSE_KEY", key)
	defer os.Unsetenv("TITO_LICENSE_KEY")
	cachedLicense = nil

	if !IsEnterprise() {
		t.Error("IsEnterprise() should return true for enterprise tier")
	}

	// Test Pro tier (should be false)
	key = generateTestKey(TierPro, "TestOrg", expiresAt)
	os.Setenv("TITO_LICENSE_KEY", key)
	cachedLicense = nil

	if IsEnterprise() {
		t.Error("IsEnterprise() should return false for pro tier")
	}

	// Test Team tier (should be false)
	key = generateTestKey(TierTeam, "TestOrg", expiresAt)
	os.Setenv("TITO_LICENSE_KEY", key)
	cachedLicense = nil

	if IsEnterprise() {
		t.Error("IsEnterprise() should return false for team tier")
	}
}

func TestGetLicenseInfo(t *testing.T) {
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	key := generateTestKey(TierPro, "TestOrg", expiresAt)

	os.Setenv("TITO_LICENSE_KEY", key)
	defer os.Unsetenv("TITO_LICENSE_KEY")
	cachedLicense = nil

	info := GetLicenseInfo()
	if info == "" {
		t.Error("GetLicenseInfo() returned empty string")
	}

	if !containsString(info, "Pro") || !containsString(info, "TestOrg") {
		t.Errorf("GetLicenseInfo() = %s, expected to contain Pro and TestOrg", info)
	}
}

func TestGetTier(t *testing.T) {
	os.Unsetenv("TITO_LICENSE_KEY")
	os.Unsetenv("TITO_SKIP_LICENSE")
	cachedLicense = nil

	if GetTier() != TierCommunity {
		t.Errorf("GetTier() should return Community when no license, got %s", GetTier())
	}

	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	key := generateTestKey(TierEnterprise, "TestOrg", expiresAt)
	os.Setenv("TITO_LICENSE_KEY", key)
	defer os.Unsetenv("TITO_LICENSE_KEY")
	cachedLicense = nil

	if GetTier() != TierEnterprise {
		t.Errorf("GetTier() should return Enterprise, got %s", GetTier())
	}
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
