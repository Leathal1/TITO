# TITO License Server

A lightweight HTTP server that generates and delivers TITO Pro license keys via Gumroad webhooks.

## Features

- **Gumroad Integration**: Receives webhook POSTs when someone purchases TITO
- **Ed25519 License Signing**: Cryptographically signs license keys
- **SQLite Storage**: Tracks all issued licenses
- **Email Delivery**: Sends license keys to customers (SMTP configurable)
- **License Validation API**: Validate license keys programmatically

## Quick Start

### 1. Generate Keypair

First, generate a fresh Ed25519 keypair:

```bash
make generate-keys
```

This creates:
- `keys/public.key` - Embed this in the TITO CLI
- `keys/private.key` - Keep this secure on the license server

### 2. Update TITO CLI

Copy the public key from `keys/public.key` and update `pkg/license/license.go`:

```go
const publicKeyB64 = "YOUR_PUBLIC_KEY_HERE"
```

Then rebuild the CLI:

```bash
cd ..
go build -o tito ./cmd/tito
```

### 3. Start the Server

```bash
make run
```

Or manually:

```bash
./license-server --port 8080 --key keys/private.key --db licenses.db
```

### 4. Configure Gumroad

In your Gumroad product settings, add a webhook:

```
https://your-server.com/webhook/gumroad
```

The server will:
1. Receive the purchase webhook
2. Generate a signed license key
3. Save it to the database
4. Email it to the customer

## API Endpoints

### POST /webhook/gumroad

Receives Gumroad purchase webhooks.

**Form Fields** (sent by Gumroad):
- `seller_id` - Your Gumroad seller ID
- `product_name` - Product name (maps to tier)
- `email` - Customer email
- `sale_id` - Unique sale identifier

**Product Name Mapping:**
- `"TITO Pro"` → Pro tier, 365 days
- `"TITO Team"` → Team tier, 365 days
- `"TITO Enterprise"` → Enterprise tier, 365 days
- `"Premium Rule Pack"` → Pro tier, 30 days (monthly)

**Response:**
```json
{
  "status": "success",
  "license_key": "tito_pro_customer_20251231_abc123...",
  "tier": "pro"
}
```

### GET /license/validate/:key

Validate a license key.

**Example:**
```bash
curl http://localhost:8080/license/validate/tito_pro_example_20251231_sig
```

**Response:**
```json
{
  "valid": true,
  "tier": "pro",
  "org": "example",
  "expires": "2025-12-31"
}
```

### GET /license/list

List all issued licenses (requires API key).

**Headers:**
- `X-API-Key: your-secret-key`

Set via environment variable:
```bash
export LICENSE_API_KEY=your-secret-key
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "service": "tito-license-server"
}
```

## Configuration

### Environment Variables

**SMTP (Email Delivery):**
```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=your-email@gmail.com
export SMTP_PASSWORD=your-app-password
export SMTP_FROM=noreply@tito.security
```

If not configured, license keys are logged to stdout instead of emailed.

**Admin API:**
```bash
export LICENSE_API_KEY=your-secret-api-key
```

### Command-Line Flags

```bash
./license-server \
  --port 8080 \
  --key keys/private.key \
  --db licenses.db \
  --seller-id YOUR_GUMROAD_SELLER_ID
```

## Deployment

### Windows Box (100.120.79.21)

1. **Transfer files:**
```bash
scp -r license-server/ anona@100.120.79.21:/opt/tito/
```

2. **Build on server:**
```bash
ssh anona@100.120.79.21
cd /opt/tito/license-server
go build -o license-server .
```

3. **Run as service** (systemd):

Create `/etc/systemd/system/tito-license.service`:
```ini
[Unit]
Description=TITO License Server
After=network.target

[Service]
Type=simple
User=anona
WorkingDirectory=/opt/tito/license-server
ExecStart=/opt/tito/license-server/license-server --port 8080 --key keys/private.key --db licenses.db
Restart=always
Environment="SMTP_HOST=smtp.gmail.com"
Environment="SMTP_PORT=587"
Environment="SMTP_USER=your-email@gmail.com"
Environment="SMTP_PASSWORD=your-app-password"
Environment="LICENSE_API_KEY=your-secret-key"

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable tito-license
sudo systemctl start tito-license
sudo systemctl status tito-license
```

4. **Expose via reverse proxy** (nginx):

```nginx
location /webhook/gumroad {
    proxy_pass http://localhost:8080/webhook/gumroad;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

## Database Schema

SQLite database (`licenses.db`):

```sql
CREATE TABLE licenses (
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
```

## Security

- **Private key**: Never commit `keys/private.key` to git
- **Database**: Restrict access to `licenses.db`
- **API key**: Use strong random key for admin endpoints
- **HTTPS**: Always use HTTPS in production (reverse proxy)
- **Gumroad validation**: Verify `seller_id` matches yours

## License Key Format

```
tito_{tier}_{orgname}_{expiry}_{ed25519_signature}
```

Example:
```
tito_pro_acmecorp_20251231_abc123def456...
```

- `tier`: community, pro, team, enterprise
- `orgname`: Derived from customer email
- `expiry`: YYYYMMDD format
- `signature`: Ed25519 signature (base64url, no padding)

## Testing

Start the server:
```bash
make run
```

Test webhook (simulate Gumroad):
```bash
curl -X POST http://localhost:8080/webhook/gumroad \
  -d "seller_id=test" \
  -d "product_name=TITO Pro" \
  -d "email=customer@example.com" \
  -d "sale_id=test-123"
```

Validate a license:
```bash
curl http://localhost:8080/license/validate/{key}
```

## Maintenance

### View logs
```bash
journalctl -u tito-license -f
```

### Backup database
```bash
cp licenses.db licenses.db.backup
```

### Query database
```bash
sqlite3 licenses.db "SELECT email, tier, issued_at FROM licenses ORDER BY issued_at DESC LIMIT 10;"
```

## Support

Issues? Contact: support@tito.security
