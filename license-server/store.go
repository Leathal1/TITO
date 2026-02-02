package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

// StoredLicense represents a license in the database
type StoredLicense struct {
	ID            int
	Key           string
	Tier          string
	Email         string
	OrgName       string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	GumroadSaleID string
}

// initStore initializes the SQLite database
func initStore(dbPath string) error {
	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Create licenses table
	schema := `
	CREATE TABLE IF NOT EXISTS licenses (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		license_key TEXT NOT NULL UNIQUE,
		tier TEXT NOT NULL,
		email TEXT NOT NULL,
		org_name TEXT NOT NULL,
		issued_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		gumroad_sale_id TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_email ON licenses(email);
	CREATE INDEX IF NOT EXISTS idx_sale_id ON licenses(gumroad_sale_id);
	`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	fmt.Println("✓ Database initialized")
	return nil
}

// saveLicenseToStore saves a license to the database
func saveLicenseToStore(key, tier, email, orgName, saleID string, expiryDays int) error {
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(time.Duration(expiryDays) * 24 * time.Hour)

	query := `
		INSERT INTO licenses (license_key, tier, email, org_name, issued_at, expires_at, gumroad_sale_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := db.Exec(query, key, tier, email, orgName, issuedAt, expiresAt, saleID)
	if err != nil {
		return fmt.Errorf("failed to insert license: %w", err)
	}

	return nil
}

// getLicenseByKey retrieves a license by its key
func getLicenseByKey(key string) (*StoredLicense, error) {
	query := `
		SELECT id, license_key, tier, email, org_name, issued_at, expires_at, gumroad_sale_id
		FROM licenses
		WHERE license_key = ?
	`

	var lic StoredLicense
	err := db.QueryRow(query, key).Scan(
		&lic.ID,
		&lic.Key,
		&lic.Tier,
		&lic.Email,
		&lic.OrgName,
		&lic.IssuedAt,
		&lic.ExpiresAt,
		&lic.GumroadSaleID,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("license not found")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	return &lic, nil
}

// getLicensesByEmail retrieves all licenses for an email
func getLicensesByEmail(email string) ([]StoredLicense, error) {
	query := `
		SELECT id, license_key, tier, email, org_name, issued_at, expires_at, gumroad_sale_id
		FROM licenses
		WHERE email = ?
		ORDER BY issued_at DESC
	`

	rows, err := db.Query(query, email)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var licenses []StoredLicense
	for rows.Next() {
		var lic StoredLicense
		err := rows.Scan(
			&lic.ID,
			&lic.Key,
			&lic.Tier,
			&lic.Email,
			&lic.OrgName,
			&lic.IssuedAt,
			&lic.ExpiresAt,
			&lic.GumroadSaleID,
		)
		if err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		licenses = append(licenses, lic)
	}

	return licenses, nil
}

// listAllLicenses retrieves all licenses (for admin use)
func listAllLicenses() ([]StoredLicense, error) {
	query := `
		SELECT id, license_key, tier, email, org_name, issued_at, expires_at, gumroad_sale_id
		FROM licenses
		ORDER BY issued_at DESC
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var licenses []StoredLicense
	for rows.Next() {
		var lic StoredLicense
		err := rows.Scan(
			&lic.ID,
			&lic.Key,
			&lic.Tier,
			&lic.Email,
			&lic.OrgName,
			&lic.IssuedAt,
			&lic.ExpiresAt,
			&lic.GumroadSaleID,
		)
		if err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		licenses = append(licenses, lic)
	}

	return licenses, nil
}
