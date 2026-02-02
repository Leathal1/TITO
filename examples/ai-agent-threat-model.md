# Threat Model Report

**Generated:** 2026-02-01 23:33 PST  
**Repository:** /tmp/ai-agent-example  
**Branch:** master  
**Language:** go  
**Framework:** stdlib  
**Architecture:** Microservices  
**Tool:** TITO (Threat In, Threat Out)  

---

## Executive Summary

TITO identified **9 threats** across **24 assets** with **169 data flows**.

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 3 |
| 🟡 Medium | 5 |
| 🟢 Low | 0 |

## 1. Assets

**Total:** 24 assets | **Exposed:** 6 | **Sensitive:** 12

| Type | Count | Exposed | Sensitive |
|------|-------|---------|----------|
| api | 6 | 6 | 0 |
| database | 6 | 0 | 6 |
| secret | 4 | 0 | 4 |
| network | 4 | 0 | 0 |
| filesystem | 3 | 0 | 1 |
| cryptography | 1 | 0 | 1 |

### Exposed Assets

| Asset | Type | Location |
|-------|------|----------|
| unknown | api | `main.go:80` |
| unknown | api | `main.go:105` |
| /v1/embeddings | api | `main.go:176` |
| /chat | api | `main.go:206` |
| /memory | api | `main.go:207` |
| /health | api | `main.go:208` |

## 2. Threats

### STRIDE-LM Distribution

| Category | Findings |
|----------|----------|
| Spoofing | 6 |
| Tampering | 82 |
| Information Disclosure | 32 |

### Findings

#### 🔴 1. Hardcoded Credential Detected

**Severity:** CRITICAL | **Risk Score:** 1.00

Hardcoded credential found: ENV: OPENAI_API_KEY at main.go:190 (3 instances across 3 files)

**STRIDE-LM:** Information Disclosure — *What's escaping?*

**Affected Locations:**

| File | Line | Asset | Type |
|------|------|-------|------|
| `main.go` | 10 | Database Operation | database |
| `main.go` | 17 | Database Operation | database |
| `main.go` | 80 | unknown | api |
| `main.go` | 92 | Database Operation | database |
| `main.go` | 105 | unknown | api |
| `main.go` | 153 | Database Insert | database |
| `main.go` | 176 | /v1/embeddings | api |
| `main.go` | 183 | Database Insert | database |
| `main.go` | 190 | ENV: OPENAI_API_KEY | secret |
| `main.go` | 191 | Database Operation | database |

*...and 6 more locations*

**Mitigations:**

- **[critical]** Encrypt data at rest and in transit
  ```
  // Add encryption for sensitive data
encrypted, err := encryptData(sensitiveData)
if err != nil {
    return err
}
// Store encrypted data
db.Exec("INSERT INTO secrets (data) VALUES (?)", encrypted)
  ```
- **[critical]** Implement secrets management systems
  ```
  // Add encryption for sensitive data
encrypted, err := encryptData(sensitiveData)
if err != nil {
    return err
}
// Store encrypted data
db.Exec("INSERT INTO secrets (data) VALUES (?)", encrypted)
  ```

---

#### 🟠 2. Sensitive Data Exposure

**Severity:** HIGH | **Risk Score:** 1.00

Sensitive data flows from main.go:190 to external endpoint main.go:43

**STRIDE-LM:** Information Disclosure — *What's escaping?*

**Affected Locations:**

| File | Line | Asset | Type |
|------|------|-------|------|
| `main.go` | 10 | Database Operation | database |
| `main.go` | 17 | Database Operation | database |
| `main.go` | 80 | unknown | api |
| `main.go` | 92 | Database Operation | database |
| `main.go` | 105 | unknown | api |
| `main.go` | 153 | Database Insert | database |
| `main.go` | 176 | /v1/embeddings | api |
| `main.go` | 183 | Database Insert | database |
| `main.go` | 190 | ENV: OPENAI_API_KEY | secret |
| `main.go` | 191 | Database Operation | database |

*...and 6 more locations*

**Mitigations:**

- **[high]** Encrypt data at rest and in transit
  ```
  // Add encryption for sensitive data
encrypted, err := encryptData(sensitiveData)
if err != nil {
    return err
}
// Store encrypted data
db.Exec("INSERT INTO secrets (data) VALUES (?)", encrypted)
  ```
- **[high]** Implement secrets management systems
  ```
  // Add encryption for sensitive data
encrypted, err := encryptData(sensitiveData)
if err != nil {
    return err
}
// Store encrypted data
db.Exec("INSERT INTO secrets (data) VALUES (?)", encrypted)
  ```

---

#### 🟠 3. LLM Integration - Prompt Injection Risk

**Severity:** HIGH | **Risk Score:** 1.00

LLM/AI framework detected at main.go:190 - susceptible to prompt injection attacks

**STRIDE-LM:** Tampering — *Can I trust what I'm seeing?*

**Affected Locations:**

| File | Line | Asset | Type |
|------|------|-------|------|
| `main.go` | 10 | Database Operation | database |
| `main.go` | 17 | Database Operation | database |
| `main.go` | 71 | File Operation | filesystem |
| `main.go` | 73 | File Operation | filesystem |
| `main.go` | 92 | Database Operation | database |
| `main.go` | 153 | Database Insert | database |
| `main.go` | 183 | Database Insert | database |
| `main.go` | 191 | Database Operation | database |

*...and 1 more locations*

**Mitigations:**

- **[high]** Sign all code and data
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```
- **[high]** Implement software bill of materials (SBOM)
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```

---

#### 🟠 4. Path Traversal Risk

**Severity:** HIGH | **Risk Score:** 1.00

File operation at main.go:71 may be vulnerable to path traversal

**STRIDE-LM:** Tampering — *Can I trust what I'm seeing?*

**Affected Locations:**

| File | Line | Asset | Type |
|------|------|-------|------|
| `main.go` | 10 | Database Operation | database |
| `main.go` | 17 | Database Operation | database |
| `main.go` | 71 | File Operation | filesystem |
| `main.go` | 73 | File Operation | filesystem |
| `main.go` | 92 | Database Operation | database |
| `main.go` | 153 | Database Insert | database |
| `main.go` | 183 | Database Insert | database |
| `main.go` | 191 | Database Operation | database |

*...and 1 more locations*

**Mitigations:**

- **[high]** Sign all code and data
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```
- **[high]** Implement software bill of materials (SBOM)
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```

---

#### 🟡 5. Unvalidated Trust Boundary Crossing

**Severity:** MEDIUM | **Risk Score:** 1.00

Data crosses trust boundary from main.go:71 to main.go:153 without apparent validation

**STRIDE-LM:** Tampering — *Can I trust what I'm seeing?*

**Affected Locations:**

| File | Line | Asset | Type |
|------|------|-------|------|
| `main.go` | 10 | Database Operation | database |
| `main.go` | 17 | Database Operation | database |
| `main.go` | 71 | File Operation | filesystem |
| `main.go` | 73 | File Operation | filesystem |
| `main.go` | 92 | Database Operation | database |
| `main.go` | 153 | Database Insert | database |
| `main.go` | 183 | Database Insert | database |
| `main.go` | 191 | Database Operation | database |

*...and 1 more locations*

**Mitigations:**

- **[medium]** Sign all code and data
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```
- **[medium]** Implement software bill of materials (SBOM)
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```

---

#### 🟡 6. Unvalidated Trust Boundary Crossing

**Severity:** MEDIUM | **Risk Score:** 1.00

Data crosses trust boundary from main.go:80 to main.go:71 without apparent validation

**STRIDE-LM:** Tampering — *Can I trust what I'm seeing?*

**Affected Locations:**

| File | Line | Asset | Type |
|------|------|-------|------|
| `main.go` | 10 | Database Operation | database |
| `main.go` | 17 | Database Operation | database |
| `main.go` | 71 | File Operation | filesystem |
| `main.go` | 73 | File Operation | filesystem |
| `main.go` | 92 | Database Operation | database |
| `main.go` | 153 | Database Insert | database |
| `main.go` | 183 | Database Insert | database |
| `main.go` | 191 | Database Operation | database |

*...and 1 more locations*

**Mitigations:**

- **[medium]** Sign all code and data
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```
- **[medium]** Implement software bill of materials (SBOM)
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```

---

#### 🟡 7. Unvalidated Trust Boundary Crossing

**Severity:** MEDIUM | **Risk Score:** 1.00

Data crosses trust boundary from main.go:80 to main.go:43 without apparent validation

**STRIDE-LM:** Tampering — *Can I trust what I'm seeing?*

**Affected Locations:**

| File | Line | Asset | Type |
|------|------|-------|------|
| `main.go` | 10 | Database Operation | database |
| `main.go` | 17 | Database Operation | database |
| `main.go` | 71 | File Operation | filesystem |
| `main.go` | 73 | File Operation | filesystem |
| `main.go` | 92 | Database Operation | database |
| `main.go` | 153 | Database Insert | database |
| `main.go` | 183 | Database Insert | database |
| `main.go` | 191 | Database Operation | database |

*...and 1 more locations*

**Mitigations:**

- **[medium]** Sign all code and data
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```
- **[medium]** Implement software bill of materials (SBOM)
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```

---

#### 🟡 8. Unvalidated Trust Boundary Crossing

**Severity:** MEDIUM | **Risk Score:** 1.00

Data crosses trust boundary from main.go:80 to main.go:10 without apparent validation

**STRIDE-LM:** Tampering — *Can I trust what I'm seeing?*

**Affected Locations:**

| File | Line | Asset | Type |
|------|------|-------|------|
| `main.go` | 10 | Database Operation | database |
| `main.go` | 17 | Database Operation | database |
| `main.go` | 71 | File Operation | filesystem |
| `main.go` | 73 | File Operation | filesystem |
| `main.go` | 92 | Database Operation | database |
| `main.go` | 153 | Database Insert | database |
| `main.go` | 183 | Database Insert | database |
| `main.go` | 191 | Database Operation | database |

*...and 1 more locations*

**Mitigations:**

- **[medium]** Sign all code and data
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```
- **[medium]** Implement software bill of materials (SBOM)
  ```
  // Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection
  ```

---

#### 🟡 9. Cryptographic Error Leakage

**Severity:** MEDIUM | **Risk Score:** 1.00

Cryptographic operation at main.go:153 may leak errors or timing information

**STRIDE-LM:** Information Disclosure — *What's escaping?*

**Affected Locations:**

| File | Line | Asset | Type |
|------|------|-------|------|
| `main.go` | 10 | Database Operation | database |
| `main.go` | 17 | Database Operation | database |
| `main.go` | 80 | unknown | api |
| `main.go` | 92 | Database Operation | database |
| `main.go` | 105 | unknown | api |
| `main.go` | 153 | Database Insert | database |
| `main.go` | 176 | /v1/embeddings | api |
| `main.go` | 183 | Database Insert | database |
| `main.go` | 190 | ENV: OPENAI_API_KEY | secret |
| `main.go` | 191 | Database Operation | database |

*...and 6 more locations*

**Mitigations:**

- **[medium]** Encrypt data at rest and in transit
  ```
  // Add encryption for sensitive data
encrypted, err := encryptData(sensitiveData)
if err != nil {
    return err
}
// Store encrypted data
db.Exec("INSERT INTO secrets (data) VALUES (?)", encrypted)
  ```
- **[medium]** Implement secrets management systems
  ```
  // Add encryption for sensitive data
encrypted, err := encryptData(sensitiveData)
if err != nil {
    return err
}
// Store encrypted data
db.Exec("INSERT INTO secrets (data) VALUES (?)", encrypted)
  ```

---

## 3. Mitigating Controls

### Recommended Actions (by priority)

| # | Priority | Control | Applies To |
|---|----------|---------|------------|
| 1 | 🔴 critical | Encrypt data at rest and in transit | 48 threats |
| 2 | 🔴 critical | Implement secrets management systems | 48 threats |
| 3 | 🟠 high | Sign all code and data | 54 threats |
| 4 | 🟠 high | Implement software bill of materials (SBOM) | 54 threats |

## Dependencies

**Total:** 1

| Package | Version |
|---------|---------|
| github.com/lib/pq | v1.10.9 |

---

*Generated by [TITO](https://github.com/Leathal1/TITO) — Threat In, Threat Out*  
*Report date: 2026-02-01 23:33 PST*
