package archetype

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetector_Microservices(t *testing.T) {
	// Create temporary directory structure
	tmpDir := t.TempDir()
	
	// Create microservices indicators
	os.MkdirAll(filepath.Join(tmpDir, "cmd", "service1"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "cmd", "service2"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "cmd", "service3"), 0755)
	
	// Create go.mod with gRPC
	goMod := `module github.com/test/microservices

go 1.21

require (
	google.golang.org/grpc v1.59.0
	github.com/gin-gonic/gin v1.9.1
)
`
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644)
	
	// Create docker-compose with multiple services
	dockerCompose := `version: '3'
services:
  api:
    build: ./cmd/api
  auth:
    build: ./cmd/auth
  worker:
    build: ./cmd/worker
`
	os.WriteFile(filepath.Join(tmpDir, "docker-compose.yml"), []byte(dockerCompose), 0644)
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("go", "gin")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	if profile.PrimaryType != ArchMicroservices {
		t.Errorf("Expected Microservices, got %s", profile.PrimaryType)
	}
	
	if profile.Confidence < 0.5 {
		t.Errorf("Expected confidence >= 0.5, got %.2f", profile.Confidence)
	}
	
	if len(profile.Signals) == 0 {
		t.Error("Expected at least one signal")
	}
}

func TestDetector_Serverless(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Create serverless indicators
	serverlessYml := `service: my-service
provider:
  name: aws
  runtime: nodejs18.x
functions:
  hello:
    handler: handler.hello
`
	os.WriteFile(filepath.Join(tmpDir, "serverless.yml"), []byte(serverlessYml), 0644)
	
	packageJSON := `{
  "name": "serverless-app",
  "dependencies": {
    "aws-lambda": "^1.0.0",
    "serverless-http": "^3.0.0"
  }
}
`
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644)
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("javascript", "serverless")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	if profile.PrimaryType != ArchServerless {
		t.Errorf("Expected Serverless, got %s", profile.PrimaryType)
	}
}

func TestDetector_CLI(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Create CLI indicators
	mainGo := `package main

import (
	"flag"
	"fmt"
)

func main() {
	flag.Parse()
	fmt.Println("Hello CLI")
}
`
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(mainGo), 0644)
	
	goMod := `module github.com/test/cli

go 1.21

require (
	github.com/spf13/cobra v1.7.0
)
`
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644)
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("go", "cobra")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	if profile.PrimaryType != ArchCLI {
		t.Errorf("Expected CLI, got %s", profile.PrimaryType)
	}
}

func TestDetector_Library(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Create library structure
	os.MkdirAll(filepath.Join(tmpDir, "pkg", "mylib"), 0755)
	
	// No main.go
	libFile := `package mylib

func DoSomething() {
	// library code
}
`
	os.WriteFile(filepath.Join(tmpDir, "pkg", "mylib", "lib.go"), []byte(libFile), 0644)
	
	goMod := `module github.com/test/mylib

go 1.21
`
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644)
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("go", "unknown")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	if profile.PrimaryType != ArchLibrary {
		t.Errorf("Expected Library, got %s", profile.PrimaryType)
	}
}

func TestDetector_WebApp(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Create web app structure
	os.MkdirAll(filepath.Join(tmpDir, "frontend"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "backend"), 0755)
	
	packageJSON := `{
  "name": "webapp",
  "dependencies": {
    "react": "^18.0.0",
    "next": "^13.0.0",
    "express": "^4.18.0"
  }
}
`
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644)
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("javascript", "nextjs")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	if profile.PrimaryType != ArchWebApp {
		t.Errorf("Expected WebApp, got %s", profile.PrimaryType)
	}
}

func TestDetector_DataPipeline(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Create data pipeline indicators
	os.MkdirAll(filepath.Join(tmpDir, "dags"), 0755)
	
	requirementsTxt := `apache-airflow==2.7.0
pandas==2.0.0
kafka-python==2.0.2
`
	os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(requirementsTxt), 0644)
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("python", "airflow")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	if profile.PrimaryType != ArchDataPipeline {
		t.Errorf("Expected DataPipeline, got %s", profile.PrimaryType)
	}
}

func TestDetector_AIML(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Create AI/ML indicators
	os.MkdirAll(filepath.Join(tmpDir, "models"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "training"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "notebooks"), 0755)
	
	requirementsTxt := `torch==2.0.0
transformers==4.30.0
langchain==0.0.200
openai==0.27.0
`
	os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(requirementsTxt), 0644)
	
	// Create a notebook
	os.WriteFile(filepath.Join(tmpDir, "notebooks", "model.ipynb"), []byte("{}"), 0644)
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("python", "pytorch")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	if profile.PrimaryType != ArchAIML {
		t.Errorf("Expected AI/ML, got %s", profile.PrimaryType)
	}
}

func TestDetector_MobileBackend(t *testing.T) {
	tmpDir := t.TempDir()
	
	packageJSON := `{
  "name": "mobile-backend",
  "dependencies": {
    "express": "^4.18.0",
    "firebase-admin": "^11.0.0",
    "fcm-node": "^1.6.0"
  }
}
`
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644)
	
	firebaseJSON := `{
  "hosting": {
    "public": "public"
  }
}
`
	os.WriteFile(filepath.Join(tmpDir, "firebase.json"), []byte(firebaseJSON), 0644)
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("javascript", "express")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	// Mobile backend signals should be present
	hasMobileSignal := false
	for _, signal := range profile.Signals {
		if signal.ArchType == ArchMobileBackend {
			hasMobileSignal = true
			break
		}
	}
	
	if !hasMobileSignal {
		t.Error("Expected mobile backend signal")
	}
}

func TestDetector_APIService(t *testing.T) {
	tmpDir := t.TempDir()
	
	mainGo := `package main

import (
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})
	r.Run()
}
`
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(mainGo), 0644)
	
	goMod := `module github.com/test/api

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
)
`
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644)
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("go", "gin")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	// Should be either API Service or Monolith (both valid for single service API)
	if profile.PrimaryType != ArchAPIService && profile.PrimaryType != ArchMonolith {
		t.Errorf("Expected APIService or Monolith, got %s", profile.PrimaryType)
	}
}

func TestDetector_Monolith(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Single service with HTTP
	os.MkdirAll(filepath.Join(tmpDir, "cmd"), 0755)
	
	mainGo := `package main

import (
	"net/http"
)

func main() {
	http.ListenAndServe(":8080", nil)
}
`
	os.WriteFile(filepath.Join(tmpDir, "cmd", "main.go"), []byte(mainGo), 0644)
	
	goMod := `module github.com/test/app

go 1.21

require (
	github.com/gorilla/mux v1.8.0
)
`
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644)
	
	// Single Dockerfile
	dockerfile := `FROM golang:1.21
WORKDIR /app
COPY . .
RUN go build -o app
CMD ["./app"]
`
	os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte(dockerfile), 0644)
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("go", "gorilla")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	// Monolith or API service are both valid
	if profile.PrimaryType != ArchMonolith && profile.PrimaryType != ArchAPIService {
		t.Errorf("Expected Monolith or APIService, got %s", profile.PrimaryType)
	}
}

func TestArchProfile_GenerateDescription(t *testing.T) {
	profile := &ArchProfile{
		PrimaryType: ArchMicroservices,
		Signals: []Signal{
			{Type: SignalDependency, Evidence: "gRPC", Weight: 0.8, ArchType: ArchMicroservices},
			{Type: SignalDependency, Evidence: "Kafka", Weight: 0.7, ArchType: ArchMicroservices},
		},
	}
	
	desc := profile.GenerateDescription("go", "gin")
	
	if desc == "" {
		t.Error("Expected non-empty description")
	}
	
	if desc != "go Microservices using gin with gRPC and Kafka" {
		t.Logf("Got description: %s", desc)
	}
}

func TestArchType_String(t *testing.T) {
	tests := []struct {
		archType ArchType
		expected string
	}{
		{ArchMonolith, "Monolith"},
		{ArchMicroservices, "Microservices"},
		{ArchServerless, "Serverless"},
		{ArchCLI, "CLI Tool"},
		{ArchLibrary, "Library/SDK"},
		{ArchAPIService, "API Service"},
		{ArchWebApp, "Web Application"},
		{ArchMobileBackend, "Mobile Backend"},
		{ArchDataPipeline, "Data Pipeline"},
		{ArchAIML, "AI/ML Service"},
		{ArchUnknown, "Unknown"},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.archType), func(t *testing.T) {
			if got := tt.archType.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestArchProfile_CalculateConfidence(t *testing.T) {
	tests := []struct {
		name     string
		profile  *ArchProfile
		minConf  float64
		maxConf  float64
	}{
		{
			name: "high confidence with multiple strong signals",
			profile: &ArchProfile{
				PrimaryType: ArchMicroservices,
				Signals: []Signal{
					{Weight: 0.9, ArchType: ArchMicroservices},
					{Weight: 0.8, ArchType: ArchMicroservices},
					{Weight: 0.7, ArchType: ArchMicroservices},
				},
			},
			minConf: 0.7,
			maxConf: 1.0,
		},
		{
			name: "medium confidence with mixed signals",
			profile: &ArchProfile{
				PrimaryType: ArchAPIService,
				Signals: []Signal{
					{Weight: 0.6, ArchType: ArchAPIService},
					{Weight: 0.5, ArchType: ArchMonolith},
					{Weight: 0.4, ArchType: ArchWebApp},
				},
			},
			minConf: 0.0,
			maxConf: 0.5,
		},
		{
			name: "no signals",
			profile: &ArchProfile{
				PrimaryType: ArchUnknown,
				Signals:     []Signal{},
			},
			minConf: 0.0,
			maxConf: 0.0,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := tt.profile.CalculateConfidence()
			if conf < tt.minConf || conf > tt.maxConf {
				t.Errorf("CalculateConfidence() = %v, want between %v and %v", conf, tt.minConf, tt.maxConf)
			}
		})
	}
}

func TestDetector_EmptyRepository(t *testing.T) {
	tmpDir := t.TempDir()
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("unknown", "unknown")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	// Should default to unknown with low confidence
	if profile.PrimaryType != ArchUnknown {
		t.Errorf("Expected Unknown for empty repo, got %s", profile.PrimaryType)
	}
	
	if profile.Confidence > 0.3 {
		t.Errorf("Expected low confidence for empty repo, got %.2f", profile.Confidence)
	}
}

func TestDetector_SecondaryTypes(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Create a microservice that's also an API service and has ML components
	os.MkdirAll(filepath.Join(tmpDir, "cmd", "api"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "cmd", "worker"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "models"), 0755)
	
	goMod := `module github.com/test/hybrid

go 1.21

require (
	google.golang.org/grpc v1.59.0
	github.com/gin-gonic/gin v1.9.1
)
`
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644)
	
	requirementsTxt := `torch==2.0.0
transformers==4.30.0
`
	os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(requirementsTxt), 0644)
	
	detector := NewDetector(tmpDir)
	profile, err := detector.Detect("go", "gin")
	
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	
	// Should identify secondary types
	if len(profile.SecondaryTypes) == 0 {
		t.Error("Expected at least one secondary type for hybrid architecture")
	}
}
