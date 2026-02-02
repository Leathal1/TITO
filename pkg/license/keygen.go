package license

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateKeyPair generates an RSA keypair for signing/verifying license keys
// This is SERVER-SIDE functionality (won't ship in CLI, useful for testing)
func GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	
	return privateKey, &privateKey.PublicKey, nil
}

// SaveKeyPair saves an RSA keypair to PEM file
func SaveKeyPair(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, path string) error {
	// Encode private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	
	// Encode public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	
	// Combine both keys in one file (for testing convenience)
	combined := append(privateKeyPEM, publicKeyPEM...)
	
	if err := os.WriteFile(path, combined, 0600); err != nil {
		return fmt.Errorf("failed to write keypair: %w", err)
	}
	
	return nil
}

// LoadKeyPair loads an RSA keypair from PEM file
func LoadKeyPair(path string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read keypair file: %w", err)
	}
	
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey
	
	// Decode PEM blocks
	rest := data
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		
		switch block.Type {
		case "RSA PRIVATE KEY":
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
			}
			
		case "RSA PUBLIC KEY":
			pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
			}
			
			var ok bool
			publicKey, ok = pubKeyInterface.(*rsa.PublicKey)
			if !ok {
				return nil, nil, fmt.Errorf("not an RSA public key")
			}
		}
		
		rest = remaining
	}
	
	if privateKey == nil || publicKey == nil {
		return nil, nil, fmt.Errorf("keypair incomplete")
	}
	
	return privateKey, publicKey, nil
}

// LicenseKeyOptions represents options for generating a license key
type LicenseKeyOptions struct {
	Tier       Tier
	Features   []string
	User       string
	OrgID      string
	ValidDays  int  // Number of days until expiration (0 = no expiration)
	IsTrial    bool
}

// GenerateLicenseKey generates a signed license key JWT
// This is SERVER-SIDE functionality (won't ship in CLI, useful for testing)
func GenerateLicenseKey(privateKey *rsa.PrivateKey, opts LicenseKeyOptions) (string, error) {
	now := time.Now()
	
	claims := Claims{
		Tier:     string(opts.Tier),
		Features: opts.Features,
		User:     opts.User,
		OrgID:    opts.OrgID,
		IsTrial:  opts.IsTrial,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(now),
			Subject:  opts.User,
		},
	}
	
	// Set expiration if specified
	if opts.ValidDays > 0 {
		expiresAt := now.Add(time.Duration(opts.ValidDays) * 24 * time.Hour)
		claims.ExpiresAt = jwt.NewNumericDate(expiresAt)
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	licenseKey, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign license: %w", err)
	}
	
	return licenseKey, nil
}

// GenerateProLicenseKey generates a Pro tier license key
func GenerateProLicenseKey(privateKey *rsa.PrivateKey, user string, validDays int) (string, error) {
	return GenerateLicenseKey(privateKey, LicenseKeyOptions{
		Tier: TierPro,
		Features: []string{
			"drift-detection",
			"llm-intelligence",
			"exploitability-scoring",
			"auto-remediation",
			"crown-jewel-discovery",
		},
		User:      user,
		ValidDays: validDays,
	})
}

// GenerateTeamLicenseKey generates a Team tier license key
func GenerateTeamLicenseKey(privateKey *rsa.PrivateKey, user, orgID string, validDays int) (string, error) {
	return GenerateLicenseKey(privateKey, LicenseKeyOptions{
		Tier: TierTeam,
		Features: []string{
			"drift-detection",
			"llm-intelligence",
			"exploitability-scoring",
			"auto-remediation",
			"crown-jewel-discovery",
			"multi-repo-scanning",
			"org-workspaces",
			"custom-threat-libraries",
			"workshop-mode",
		},
		User:      user,
		OrgID:     orgID,
		ValidDays: validDays,
	})
}

// GenerateEnterpriseLicenseKey generates an Enterprise tier license key
func GenerateEnterpriseLicenseKey(privateKey *rsa.PrivateKey, user, orgID string, validDays int) (string, error) {
	return GenerateLicenseKey(privateKey, LicenseKeyOptions{
		Tier: TierEnterprise,
		Features: []string{
			"drift-detection",
			"llm-intelligence",
			"exploitability-scoring",
			"auto-remediation",
			"crown-jewel-discovery",
			"multi-repo-scanning",
			"org-workspaces",
			"custom-threat-libraries",
			"workshop-mode",
			"attack-simulation",
			"compliance-evidence",
			"threat-intel-feed",
			"sso-saml",
			"api-access",
			"priority-support",
		},
		User:      user,
		OrgID:     orgID,
		ValidDays: validDays,
	})
}

// VerifyLicenseSignature verifies that a license key was signed with the correct private key
func VerifyLicenseSignature(licenseKey string, publicKey *rsa.PublicKey) error {
	token, err := jwt.ParseWithClaims(licenseKey, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	
	if !token.Valid {
		return fmt.Errorf("invalid token")
	}
	
	return nil
}
