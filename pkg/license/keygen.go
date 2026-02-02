package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"time"
)

// GenerateKeyPair generates an Ed25519 keypair for signing/verifying license keys
// This is SERVER-SIDE functionality (won't ship in CLI, used by license server)
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}
	return publicKey, privateKey, nil
}

// SaveKeyPair saves an Ed25519 keypair to separate files
func SaveKeyPair(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, publicPath, privatePath string) error {
	// Save public key (base64 encoded for embedding in code)
	pubKeyB64 := base64.StdEncoding.EncodeToString(publicKey)
	if err := os.WriteFile(publicPath, []byte(pubKeyB64), 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	// Save private key (base64 encoded for server use)
	privKeyB64 := base64.StdEncoding.EncodeToString(privateKey)
	if err := os.WriteFile(privatePath, []byte(privKeyB64), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// LoadPrivateKey loads an Ed25519 private key from a base64-encoded file
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	return ed25519.PrivateKey(privateKey), nil
}

// LoadPublicKey loads an Ed25519 public key from a base64-encoded file
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(publicKey))
	}

	return ed25519.PublicKey(publicKey), nil
}

// GenerateLicenseKey generates a signed license key using Ed25519
// Key format: tito_{tier}_{orgname}_{expiry}_{ed25519_signature_base64url}
// This is SERVER-SIDE functionality (used by license server)
func GenerateLicenseKey(privateKey ed25519.PrivateKey, tier Tier, orgName string, expiryDays int) (string, error) {
	// Calculate expiry date
	expiresAt := time.Now().Add(time.Duration(expiryDays) * 24 * time.Hour)
	expiryStr := expiresAt.Format("20060102")

	// Build payload to sign
	payload := fmt.Sprintf("tito_%s_%s_%s", tier, orgName, expiryStr)

	// Sign payload with Ed25519
	signature := ed25519.Sign(privateKey, []byte(payload))

	// Encode signature as base64url (without padding)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Build final license key
	licenseKey := fmt.Sprintf("tito_%s_%s_%s_%s", tier, orgName, expiryStr, signatureB64)

	return licenseKey, nil
}

// GenerateProLicenseKey generates a Pro tier license key
func GenerateProLicenseKey(privateKey ed25519.PrivateKey, orgName string, validDays int) (string, error) {
	return GenerateLicenseKey(privateKey, TierPro, orgName, validDays)
}

// GenerateTeamLicenseKey generates a Team tier license key
func GenerateTeamLicenseKey(privateKey ed25519.PrivateKey, orgName string, validDays int) (string, error) {
	return GenerateLicenseKey(privateKey, TierTeam, orgName, validDays)
}

// GenerateEnterpriseLicenseKey generates an Enterprise tier license key
func GenerateEnterpriseLicenseKey(privateKey ed25519.PrivateKey, orgName string, validDays int) (string, error) {
	return GenerateLicenseKey(privateKey, TierEnterprise, orgName, validDays)
}

// VerifyLicenseSignature verifies that a license key has a valid Ed25519 signature
func VerifyLicenseSignature(licenseKey string, publicKey ed25519.PublicKey) error {
	// Parse the license key
	license, err := ValidateLicenseKey(licenseKey)
	if err != nil {
		return fmt.Errorf("invalid license key: %w", err)
	}

	// If we got here, the signature is valid (ValidateLicenseKey checks it)
	_ = license
	return nil
}
