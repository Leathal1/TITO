package license

import (
	"os"
	"testing"
	"time"
)

func TestValidateLicenseKey(t *testing.T) {
	// Generate a test license key
	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	key := GenerateLicenseKey(TierPro, "TestOrg", expiresAt)

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

func TestValidateLicenseKey_Expired(t *testing.T) {
	// Generate an expired license
	expiresAt := time.Now().Add(-24 * time.Hour) // Expired yesterday
	key := GenerateLicenseKey(TierPro, "TestOrg", expiresAt)

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

func TestCheckLicense_SkipFlag(t *testing.T) {
	// Set skip flag
	os.Setenv("TITO_SKIP_LICENSE", "1")
	defer os.Unsetenv("TITO_SKIP_LICENSE")

	// Clear cache
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
	// Generate a test license
	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	key := GenerateLicenseKey(TierPro, "EnvTest", expiresAt)

	os.Setenv("TITO_LICENSE_KEY", key)
	defer os.Unsetenv("TITO_LICENSE_KEY")

	// Clear cache and skip flag
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

func TestCheckLicense_Free(t *testing.T) {
	// Clear all license sources
	os.Unsetenv("TITO_LICENSE_KEY")
	os.Unsetenv("TITO_SKIP_LICENSE")
	cachedLicense = nil

	license, err := CheckLicense()
	if err != nil {
		t.Fatalf("CheckLicense failed: %v", err)
	}

	if license.Tier != TierFree {
		t.Errorf("Expected free tier, got %s", license.Tier)
	}
}

func TestIsPro(t *testing.T) {
	tests := []struct {
		name     string
		tier     Tier
		expected bool
	}{
		{"Free tier", TierFree, false},
		{"Pro tier", TierPro, true},
		{"Enterprise tier", TierEnterprise, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up license
			expiresAt := time.Now().Add(365 * 24 * time.Hour)
			key := GenerateLicenseKey(tt.tier, "TestOrg", expiresAt)

			if tt.tier == TierFree {
				os.Unsetenv("TITO_LICENSE_KEY")
				os.Unsetenv("TITO_SKIP_LICENSE")
			} else {
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

func TestIsEnterprise(t *testing.T) {
	// Test Enterprise tier
	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	key := GenerateLicenseKey(TierEnterprise, "TestOrg", expiresAt)

	os.Setenv("TITO_LICENSE_KEY", key)
	defer os.Unsetenv("TITO_LICENSE_KEY")
	cachedLicense = nil

	if !IsEnterprise() {
		t.Error("IsEnterprise() should return true for enterprise tier")
	}

	// Test Pro tier (should be false)
	key = GenerateLicenseKey(TierPro, "TestOrg", expiresAt)
	os.Setenv("TITO_LICENSE_KEY", key)
	cachedLicense = nil

	if IsEnterprise() {
		t.Error("IsEnterprise() should return false for pro tier")
	}
}

func TestGetLicenseInfo(t *testing.T) {
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	key := GenerateLicenseKey(TierPro, "TestOrg", expiresAt)

	os.Setenv("TITO_LICENSE_KEY", key)
	defer os.Unsetenv("TITO_LICENSE_KEY")
	cachedLicense = nil

	info := GetLicenseInfo()
	if info == "" {
		t.Error("GetLicenseInfo() returned empty string")
	}

	// Should contain tier and org name
	if !containsString(info, "Pro") || !containsString(info, "TestOrg") {
		t.Errorf("GetLicenseInfo() = %s, expected to contain Pro and TestOrg", info)
	}
}

func TestGenerateHMAC(t *testing.T) {
	message := "test_message"
	secret := "test_secret"

	sig1 := generateHMAC(message, secret)
	sig2 := generateHMAC(message, secret)

	if sig1 != sig2 {
		t.Error("generateHMAC should be deterministic")
	}

	// Different message should produce different signature
	sig3 := generateHMAC("different_message", secret)
	if sig1 == sig3 {
		t.Error("Different messages should produce different signatures")
	}
}

func TestVerifyHMAC(t *testing.T) {
	message := "test_message"
	secret := "test_secret"

	signature := generateHMAC(message, secret)

	if !verifyHMAC(message, signature, secret) {
		t.Error("verifyHMAC should validate correct signature")
	}

	if verifyHMAC(message, "wrong_signature", secret) {
		t.Error("verifyHMAC should reject incorrect signature")
	}

	if verifyHMAC("wrong_message", signature, secret) {
		t.Error("verifyHMAC should reject wrong message")
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
