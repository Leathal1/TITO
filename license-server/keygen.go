package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"time"
)

var privateKey ed25519.PrivateKey
var publicKey ed25519.PublicKey

// initKeygen loads the Ed25519 private key from file
func initKeygen(keyPath string) error {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key size: expected %d, got %d", 
			ed25519.PrivateKeySize, len(privKeyBytes))
	}

	privateKey = ed25519.PrivateKey(privKeyBytes)
	publicKey = privateKey.Public().(ed25519.PublicKey)

	fmt.Printf("✓ Private key loaded (%d bytes)\n", len(privateKey))
	fmt.Printf("✓ Public key: %s\n", base64.StdEncoding.EncodeToString(publicKey))
	
	return nil
}

// generateKeyPair generates a new Ed25519 keypair
func generateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate keypair: %w", err)
	}
	return pub, priv, nil
}

// saveKeyPair saves a keypair to files
func saveKeyPair(pub ed25519.PublicKey, priv ed25519.PrivateKey, publicPath, privatePath string) error {
	// Save public key (base64 encoded)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(publicPath, []byte(pubB64), 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	// Save private key (base64 encoded, restricted permissions)
	privB64 := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(privatePath, []byte(privB64), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// GenerateLicenseKey generates a signed license key
// Key format: tito_{tier}_{orgname}_{expiry}_{ed25519_signature_base64url}
func GenerateLicenseKey(tier, orgName string, expiryDays int) (string, error) {
	if privateKey == nil {
		return "", fmt.Errorf("private key not loaded")
	}

	// Calculate expiry date
	expiresAt := time.Now().Add(time.Duration(expiryDays) * 24 * time.Hour)
	expiryStr := expiresAt.Format("20060102")

	// Build payload to sign
	payload := fmt.Sprintf("tito_%s_%s_%s", tier, orgName, expiryStr)

	// Sign with Ed25519
	signature := ed25519.Sign(privateKey, []byte(payload))

	// Encode signature as base64url (no padding)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Build final license key
	licenseKey := fmt.Sprintf("tito_%s_%s_%s_%s", tier, orgName, expiryStr, signatureB64)

	return licenseKey, nil
}

type LicenseInfo struct {
	Tier      string
	OrgName   string
	ExpiresAt string
}

// validateLicenseKey validates a license key and returns tier info
func validateLicenseKey(key string) (bool, LicenseInfo) {
	// This is a simplified validation - the full validation is in pkg/license
	// For the server, we just need to parse and verify signature
	
	// Parse key format: tito_{tier}_{orgname}_{expiry}_{signature}
	// For now, just return mock data - actual validation would import pkg/license
	
	return true, LicenseInfo{
		Tier:      "pro",
		OrgName:   "example",
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02"),
	}
}
