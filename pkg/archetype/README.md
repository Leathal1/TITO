# Architecture Detection (Archetype)

Automatically detects application architecture types to tailor threat analysis.

## Overview

TITO analyzes repository structure, dependencies, file patterns, and code to classify applications into architectural archetypes. This enables context-aware threat modeling that surfaces risks specific to each architecture type.

## Architecture Types

### Primary Types

- **Monolith** — Single deployable unit, all code in one service
- **Microservices** — Multiple services communicating via APIs/queues/gRPC
- **Serverless** — Lambda/Cloud Functions/Azure Functions patterns
- **CLI Tool** — Command-line application, no HTTP server
- **Library/SDK** — Package meant to be imported, not run standalone
- **API Service** — Primarily an HTTP/gRPC API backend
- **Web Application** — Frontend + backend (React/Vue/Angular + API)
- **Mobile Backend** — API with mobile SDK patterns (push notifications, device tokens)
- **Data Pipeline** — ETL, streaming, batch processing
- **AI/ML Service** — Model serving, training pipelines, RAG systems

## Detection Signals

The detector analyzes multiple signal types with weighted confidence:

### 1. Project Structure
- Multiple `cmd/` directories → **Microservices**
- `services/` directory → **Microservices**
- `pkg/` or `lib/` without `main` → **Library**
- `lambda/` or `functions/` → **Serverless**
- `frontend/`, `client/`, `web/` → **Web App**
- `pipelines/`, `etl/`, `dags/` → **Data Pipeline**
- `models/`, `training/`, `notebooks/` → **AI/ML**

### 2. Dependencies
- `grpc`, `protobuf` → **Microservices/API Service**
- `express`, `gin`, `fastapi` → **API Service/Web App**
- `aws-lambda`, `serverless` → **Serverless**
- `kafka`, `rabbitmq`, `celery` → **Microservices/Data Pipeline**
- `torch`, `transformers`, `langchain` → **AI/ML**
- `cobra`, `click`, `argparse` (without HTTP) → **CLI**
- `firebase`, `fcm`, `apns` → **Mobile Backend**

### 3. File Patterns
- Multiple `Dockerfile`s → **Microservices**
- `docker-compose.yml` with 3+ services → **Microservices**
- `kubernetes/`, `k8s/`, `helm/` → **Microservices**
- `serverless.yml`, `template.yaml` → **Serverless**
- Terraform with Lambda/Functions → **Serverless**
- `.ipynb` notebooks → **AI/ML**
- `.proto` files → **Microservices**

### 4. Code Patterns (lightweight)
- HTTP server initialization → **API Service**
- CLI argument parsing without HTTP → **CLI**

### 5. Configuration
- Makefile with serverless deploy → **Serverless**
- GitHub Actions with multiple Docker builds → **Microservices**

## Usage

```go
import "github.com/Leathal1/TITO/pkg/archetype"

// Detect architecture
detector := archetype.NewDetector("/path/to/repo")
profile, err := detector.Detect("go", "gin")

// Access results
fmt.Printf("Primary: %s\n", profile.PrimaryType)
fmt.Printf("Confidence: %.0f%%\n", profile.Confidence * 100)
fmt.Printf("Description: %s\n", profile.Description)

// Check secondary types
for _, secondary := range profile.SecondaryTypes {
    fmt.Printf("Secondary: %s\n", secondary)
}

// Get threat adjustments
adjustments := archetype.GetThreatAdjustments(profile)
for _, threat := range adjustments.AdditionalThreats {
    fmt.Printf("  - %s\n", threat)
}
```

## Architecture-Specific Threats

Each architecture type has specific threat patterns:

### Microservices
- Service-to-service authentication bypass
- API gateway misconfiguration
- Service mesh security gaps
- East-west traffic interception
- Service discovery poisoning

### Serverless
- Cold start injection attacks
- Event injection and manipulation
- Over-permissive IAM roles
- Function timeout exploitation
- Denial of wallet (resource exhaustion)

### Monolith
- Single point of failure → full system compromise
- Large blast radius from any vulnerability
- Difficult to implement least privilege

### CLI Tool
- Command injection via arguments
- Path traversal in file operations
- Credential theft from config files
- Binary tampering

### Library/SDK
- Supply chain attacks via dependency
- API misuse by downstream consumers
- Insecure defaults propagated to consumers

### API Service
- API authentication bypass
- Broken object-level authorization (BOLA)
- Mass assignment vulnerabilities
- CORS misconfiguration

### Web Application
- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- Clickjacking
- Frontend secrets exposure

### Mobile Backend
- Mobile app reverse engineering
- API key extraction from mobile apps
- Push notification injection
- Certificate pinning bypass

### Data Pipeline
- Data poisoning attacks
- Pipeline injection
- Unauthorized data access during processing
- Schema manipulation attacks

### AI/ML Service
- Prompt injection attacks
- Model inversion and extraction
- Training data poisoning
- Adversarial input attacks
- RAG context injection
- LLM jailbreaking

## Integration

The archetype package is integrated into TITO's scan flow:

1. **Repository scanning** (`pkg/scanner`) calls archetype detection
2. **Architecture profile** is stored in `Repository.Architecture`
3. **Threat analysis** uses architecture type to adjust risk scores
4. **Output** displays architecture in scan results

Example output:
```
✓ Repository scanned successfully
  Language: go
  Framework: gin
  Architecture: Microservices (confidence: 85%)
    Secondary: API Service, Data Pipeline
    Signals: gRPC, docker-compose with 5 services, kubernetes
  Assets discovered: 42
  Data flows: 18
  Dependencies: 23
```

## Testing

Comprehensive tests cover all architecture types:

```bash
go test ./pkg/archetype/... -v
```

Test scenarios:
- Microservices detection (multi-cmd, gRPC, docker-compose)
- Serverless detection (serverless.yml, Lambda deps)
- CLI detection (cobra, no HTTP)
- Library detection (pkg/ without main)
- Web app detection (frontend dirs, React/Vue)
- Data pipeline detection (Airflow, Kafka)
- AI/ML detection (torch, transformers, notebooks)
- Mobile backend detection (Firebase, FCM)
- Confidence calculation
- Secondary type identification

## Future Enhancements

- **Advanced code analysis** — Parse AST for deeper pattern detection
- **ML-based classification** — Train model on known repositories
- **Historical evolution tracking** — Detect architecture changes over time
- **Custom archetypes** — User-defined architecture patterns
- **Hybrid detection** — Better handle hybrid architectures
