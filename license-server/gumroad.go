package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// GumroadPurchase represents a Gumroad webhook payload
type GumroadPurchase struct {
	SellerID    string
	ProductID   string
	ProductName string
	Price       string
	Email       string
	SaleID      string
	PurchaseDate time.Time
}

// handleGumroadWebhook processes Gumroad webhook POST requests
func handleGumroadWebhook(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received Gumroad webhook from %s", r.RemoteAddr)

	// Parse form data
	if err := r.ParseForm(); err != nil {
		log.Printf("Failed to parse form: %v", err)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Extract purchase data
	purchase := GumroadPurchase{
		SellerID:    r.FormValue("seller_id"),
		ProductID:   r.FormValue("product_id"),
		ProductName: r.FormValue("product_name"),
		Price:       r.FormValue("price"),
		Email:       r.FormValue("email"),
		SaleID:      r.FormValue("sale_id"),
	}

	// Validate seller ID if configured
	if *gumroadSeller != "" && purchase.SellerID != *gumroadSeller {
		log.Printf("Invalid seller ID: got %s, expected %s", purchase.SellerID, *gumroadSeller)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	log.Printf("Purchase: %s bought '%s' (%s) for %s", 
		purchase.Email, purchase.ProductName, purchase.ProductID, purchase.Price)

	// Map product to tier and expiry
	tier, expiryDays := mapProductToTier(purchase.ProductName)
	if tier == "" {
		log.Printf("Unknown product: %s", purchase.ProductName)
		http.Error(w, "Unknown product", http.StatusBadRequest)
		return
	}

	// Extract org name from email (use domain or email prefix)
	orgName := extractOrgName(purchase.Email)

	// Generate license key
	licenseKey, err := GenerateLicenseKey(tier, orgName, expiryDays)
	if err != nil {
		log.Printf("Failed to generate license: %v", err)
		http.Error(w, "Failed to generate license", http.StatusInternalServerError)
		return
	}

	log.Printf("Generated %s license for %s: %s", tier, purchase.Email, licenseKey)

	// Save license to database
	if err := saveLicenseToStore(licenseKey, tier, purchase.Email, orgName, purchase.SaleID, expiryDays); err != nil {
		log.Printf("Failed to save license: %v", err)
		// Continue anyway - we have the key
	}

	// Send license via email
	if err := sendLicenseEmail(purchase.Email, licenseKey, tier); err != nil {
		log.Printf("Failed to send email: %v", err)
		// Log but don't fail - admin can manually send
	}

	// Return success with license key
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"success","license_key":"%s","tier":"%s"}`, licenseKey, tier)
}

// mapProductToTier maps Gumroad product names to TITO tiers and expiry days
func mapProductToTier(productName string) (string, int) {
	productName = strings.ToLower(productName)

	switch {
	case strings.Contains(productName, "tito pro"):
		return "pro", 365
	case strings.Contains(productName, "tito team"):
		return "team", 365
	case strings.Contains(productName, "tito enterprise"):
		return "enterprise", 365
	case strings.Contains(productName, "premium rule pack"):
		// Monthly subscription
		return "pro", 30
	default:
		return "", 0
	}
}

// extractOrgName extracts organization name from email
func extractOrgName(email string) string {
	// Use email prefix as org name (before @)
	parts := strings.Split(email, "@")
	if len(parts) > 0 {
		return strings.ReplaceAll(parts[0], ".", "-")
	}
	return "customer"
}
