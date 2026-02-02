package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

var (
	port          = flag.Int("port", 8080, "HTTP server port")
	privateKeyPath = flag.String("key", "keys/private.key", "Path to Ed25519 private key")
	dbPath        = flag.String("db", "licenses.db", "Path to SQLite database")
	gumroadSeller = flag.String("seller-id", "", "Gumroad seller ID for webhook validation")
)

func main() {
	flag.Parse()

	// Initialize license key generator
	if err := initKeygen(*privateKeyPath); err != nil {
		log.Fatalf("Failed to initialize keygen: %v", err)
	}

	// Initialize database
	if err := initStore(*dbPath); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Setup router
	r := mux.NewRouter()

	// Routes
	r.HandleFunc("/health", handleHealth).Methods("GET")
	r.HandleFunc("/webhook/gumroad", handleGumroadWebhook).Methods("POST")
	r.HandleFunc("/license/validate/{key}", handleValidateLicense).Methods("GET")
	r.HandleFunc("/license/list", handleListLicenses).Methods("GET")

	// Start server
	addr := fmt.Sprintf(":%d", *port)
	fmt.Printf("🚀 TITO License Server starting on %s\n", addr)
	fmt.Printf("   Private key: %s\n", *privateKeyPath)
	fmt.Printf("   Database: %s\n", *dbPath)
	if *gumroadSeller != "" {
		fmt.Printf("   Gumroad seller ID: %s\n", *gumroadSeller)
	}
	fmt.Println()

	log.Fatal(http.ListenAndServe(addr, r))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","service":"tito-license-server"}`)
}

func handleValidateLicense(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["key"]

	isValid, info := validateLicenseKey(key)
	
	w.Header().Set("Content-Type", "application/json")
	if isValid {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"valid":true,"tier":"%s","org":"%s","expires":"%s"}`, 
			info.Tier, info.OrgName, info.ExpiresAt)
	} else {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"valid":false,"error":"invalid or expired license"}`)
	}
}

func handleListLicenses(w http.ResponseWriter, r *http.Request) {
	// Optional: require API key for this endpoint
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" || apiKey != os.Getenv("LICENSE_API_KEY") {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"unauthorized"}`)
		return
	}

	licenses, err := listAllLicenses()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	// Simple JSON encoding
	fmt.Fprintf(w, `{"licenses":[`)
	for i, lic := range licenses {
		if i > 0 {
			fmt.Fprintf(w, ",")
		}
		fmt.Fprintf(w, `{"key":"%s","tier":"%s","email":"%s","org":"%s","issued":"%s","expires":"%s"}`,
			lic.Key, lic.Tier, lic.Email, lic.OrgName, lic.IssuedAt, lic.ExpiresAt)
	}
	fmt.Fprintf(w, `]}`)
}
