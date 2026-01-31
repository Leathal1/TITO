package dataflow

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Generator3D generates 3D data flow diagrams
type Generator3D struct{}

// NewGenerator3D creates a new 3D data flow diagram generator
func NewGenerator3D() *Generator3D {
	return &Generator3D{}
}

// Generate3D generates a 3D visualization from diagram data
func (g *Generator3D) Generate3D(data *DiagramData, outputPath string) error {
	// Convert diagram data to JSON
	diagramJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal diagram data: %w", err)
	}

	// Replace placeholder in template
	html := htmlTemplate3D
	html = strings.Replace(html, "{{DIAGRAM_DATA}}", string(diagramJSON), 1)
	html = strings.Replace(html, "{{ATTACK_PATHS}}", "[]", 1) // No attack paths
	html = strings.Replace(html, "{{TITLE}}", data.Metadata.Title, -1)

	// Write to file
	if err := os.WriteFile(outputPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write 3D diagram: %w", err)
	}

	return nil
}

// Generate3DWithAttackPaths generates a 3D visualization with attack path overlay
func (g *Generator3D) Generate3DWithAttackPaths(data *DiagramData, paths interface{}, outputPath string) error {
	// Convert diagram data to JSON
	diagramJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal diagram data: %w", err)
	}

	// Convert attack paths to JSON
	pathsJSON, err := json.MarshalIndent(paths, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal attack paths: %w", err)
	}

	// Replace placeholders in template
	html := htmlTemplate3D
	html = strings.Replace(html, "{{DIAGRAM_DATA}}", string(diagramJSON), 1)
	html = strings.Replace(html, "{{ATTACK_PATHS}}", string(pathsJSON), 1)
	html = strings.Replace(html, "{{TITLE}}", data.Metadata.Title, -1)

	// Write to file
	if err := os.WriteFile(outputPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write 3D diagram with attack paths: %w", err)
	}

	return nil
}
