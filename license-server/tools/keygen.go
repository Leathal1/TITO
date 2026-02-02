package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	// Generate Ed25519 keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate keypair: %v\n", err)
		os.Exit(1)
	}

	// Encode as base64
	pubKeyB64 := base64.StdEncoding.EncodeToString(publicKey)
	privKeyB64 := base64.StdEncoding.EncodeToString(privateKey)

	// Save to files
	if err := os.WriteFile("keys/public.key", []byte(pubKeyB64), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write public key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile("keys/private.key", []byte(privKeyB64), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write private key: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Println("✓ Ed25519 keypair generated successfully!")
	fmt.Println()
	fmt.Println("Public key (for embedding in CLI):")
	fmt.Printf("  %s\n", pubKeyB64)
	fmt.Println()
	fmt.Println("Private key location (keep secure!):")
	fmt.Println("  keys/private.key")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Copy the public key above")
	fmt.Println("  2. Update pkg/license/license.go:")
	fmt.Printf("     const publicKeyB64 = \"%s\"\n", pubKeyB64)
	fmt.Println("  3. Rebuild TITO CLI: cd .. && go build -o tito ./cmd/tito")
	fmt.Println("  4. Add keys/ to .gitignore (already done)")
}
