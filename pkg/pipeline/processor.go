package pipeline

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/stridelm"
)

// Processor processes threats through the intelligence pipeline
// Collection → Normalization → Enrichment → Deduplication → Prioritization → Filtering
type Processor struct {
	config  ProcessorConfig
	metrics PipelineMetrics
	mu      sync.Mutex
}

// ProcessorConfig holds pipeline configuration
type ProcessorConfig struct {
	MinPriority float64 // Filter out threats below this priority
	MaxAgeDays  int     // Filter out threats older than this
}

// PipelineMetrics tracks pipeline statistics
type PipelineMetrics struct {
	Input        int
	Normalized   int
	Enriched     int
	Deduplicated int
	Prioritized  int
	Filtered     int
}

// NewProcessor creates a new threat processor
func NewProcessor(config ProcessorConfig) *Processor {
	return &Processor{
		config: config,
	}
}

// Process processes a batch of threats through the pipeline
func (p *Processor) Process(ctx context.Context, threats []*models.Threat) ([]*models.Threat, error) {
	p.mu.Lock()
	p.metrics = PipelineMetrics{Input: len(threats)}
	p.mu.Unlock()

	// Stage 1: Normalize
	threats = p.normalize(threats)
	p.recordMetric("normalized", len(threats))

	// Stage 2: Enrich
	threats = p.enrich(ctx, threats)
	p.recordMetric("enriched", len(threats))

	// Stage 3: Deduplicate
	threats = p.deduplicate(threats)
	p.recordMetric("deduplicated", len(threats))

	// Stage 4: Prioritize
	threats = p.prioritize(threats)
	p.recordMetric("prioritized", len(threats))

	// Stage 5: Filter
	threats = p.filter(threats)
	p.recordMetric("filtered", len(threats))

	return threats, nil
}

// normalize ensures consistent data format
func (p *Processor) normalize(threats []*models.Threat) []*models.Threat {
	normalized := make([]*models.Threat, 0, len(threats))

	for _, threat := range threats {
		// Ensure title is not empty
		if threat.Title == "" {
			if len(threat.Description) > 100 {
				threat.Title = threat.Description[:100]
			} else if len(threat.Description) > 0 {
				threat.Title = threat.Description
			} else {
				threat.Title = "Untitled Threat"
			}
		}

		// Ensure timestamps are set
		if threat.DiscoveredAt.IsZero() {
			threat.DiscoveredAt = time.Now()
		}
		if threat.UpdatedAt.IsZero() {
			threat.UpdatedAt = time.Now()
		}

		// Normalize tags to lowercase
		normalizedTags := make([]string, len(threat.Tags))
		for i, tag := range threat.Tags {
			normalizedTags[i] = toLower(tag)
		}
		threat.Tags = normalizedTags

		normalized = append(normalized, threat)
	}

	return normalized
}

// enrich adds contextual information to threats
func (p *Processor) enrich(ctx context.Context, threats []*models.Threat) []*models.Threat {
	// Use goroutines for concurrent enrichment
	enriched := make([]*models.Threat, len(threats))
	var wg sync.WaitGroup

	for i, threat := range threats {
		wg.Add(1)
		go func(idx int, t *models.Threat) {
			defer wg.Done()

			// Enrichment 1: Check asset relevance
			t.Context.AffectsKnownAssets = p.checkAssetRelevance(t)

			// Enrichment 2: Check exploitation status
			// (Real implementation would query CISA KEV, exploit-db, etc.)

			// Enrichment 3: Add detection rules from STRIDE-LM
			if t.StrideProfile != nil {
				categoryInfo := getAllCategories()[t.StrideProfile.PrimaryCategory]
				if len(categoryInfo.DetectionStrategies) >= 3 {
					t.DetectionRules = categoryInfo.DetectionStrategies[0:3]
				}
			}

			enriched[idx] = t
		}(i, threat)
	}

	wg.Wait()
	return enriched
}

// deduplicate removes duplicate threats
func (p *Processor) deduplicate(threats []*models.Threat) []*models.Threat {
	seen := make(map[string]*models.Threat)
	deduplicated := make([]*models.Threat, 0, len(threats))

	for _, threat := range threats {
		key := p.generateDedupKey(threat)

		if existing, exists := seen[key]; exists {
			// Merge into existing
			p.mergeThreats(existing, threat)
		} else {
			seen[key] = threat
			deduplicated = append(deduplicated, threat)
		}
	}

	return deduplicated
}

// prioritize calculates and updates priority scores
func (p *Processor) prioritize(threats []*models.Threat) []*models.Threat {
	for _, threat := range threats {
		threat.UpdatePriority()
	}

	// Sort by priority (highest first)
	sortByPriority(threats)

	return threats
}

// filter removes low-quality threats
func (p *Processor) filter(threats []*models.Threat) []*models.Threat {
	filtered := make([]*models.Threat, 0, len(threats))

	maxAge := time.Duration(p.config.MaxAgeDays) * 24 * time.Hour

	for _, threat := range threats {
		// Skip false positives
		if threat.FalsePositive {
			continue
		}

		// Skip very low priority
		if threat.PriorityScore < p.config.MinPriority {
			continue
		}

		// Skip too old
		age := time.Since(threat.DiscoveredAt)
		if age > maxAge {
			continue
		}

		filtered = append(filtered, threat)
	}

	return filtered
}

// generateDedupKey generates a deduplication key for a threat
func (p *Processor) generateDedupKey(threat *models.Threat) string {
	// CVEs dedupe by CVE ID
	if len(threat.CVEIDs) > 0 {
		return "cve:" + threat.CVEIDs[0]
	}

	// IOCs dedupe by first indicator value
	if len(threat.Indicators) > 0 {
		ind := threat.Indicators[0]
		return fmt.Sprintf("ioc:%s:%s", ind.Type, ind.Value)
	}

	// Others dedupe by title
	titleKey := threat.Title
	if len(titleKey) > 100 {
		titleKey = titleKey[:100]
	}
	return "title:" + titleKey
}

// mergeThreats merges new threat data into existing threat
func (p *Processor) mergeThreats(existing, new *models.Threat) {
	// Update timestamp
	existing.UpdatedAt = time.Now()

	// Merge indicators
	existingValues := make(map[string]bool)
	for _, ind := range existing.Indicators {
		existingValues[ind.Value] = true
	}

	for _, ind := range new.Indicators {
		if !existingValues[ind.Value] {
			existing.Indicators = append(existing.Indicators, ind)
		}
	}

	// Merge tags
	existingTags := make(map[string]bool)
	for _, tag := range existing.Tags {
		existingTags[tag] = true
	}
	for _, tag := range new.Tags {
		if !existingTags[tag] {
			existing.Tags = append(existing.Tags, tag)
		}
	}

	// Merge source feeds
	existingFeeds := make(map[string]bool)
	for _, feed := range existing.SourceFeeds {
		existingFeeds[feed] = true
	}
	for _, feed := range new.SourceFeeds {
		if !existingFeeds[feed] {
			existing.SourceFeeds = append(existing.SourceFeeds, feed)
		}
	}

	// Take higher severity
	if new.Severity.Score() > existing.Severity.Score() {
		existing.Severity = new.Severity
	}

	// Recalculate priority
	existing.UpdatePriority()
}

// checkAssetRelevance checks if threat affects known assets (stub)
func (p *Processor) checkAssetRelevance(threat *models.Threat) bool {
	// Real implementation would query asset inventory
	// For now, mark high severity as affecting assets
	return threat.Severity.Score() >= 7
}

// recordMetric records a pipeline metric
func (p *Processor) recordMetric(stage string, count int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch stage {
	case "normalized":
		p.metrics.Normalized = count
	case "enriched":
		p.metrics.Enriched = count
	case "deduplicated":
		p.metrics.Deduplicated = count
	case "prioritized":
		p.metrics.Prioritized = count
	case "filtered":
		p.metrics.Filtered = count
	}
}

// GetMetrics returns the current pipeline metrics
func (p *Processor) GetMetrics() PipelineMetrics {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.metrics
}

// Helper functions

func toLower(s string) string {
	result := ""
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			result += string(r + 32)
		} else {
			result += string(r)
		}
	}
	return result
}

func sortByPriority(threats []*models.Threat) {
	// Simple bubble sort by priority (descending)
	n := len(threats)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if threats[j].PriorityScore < threats[j+1].PriorityScore {
				threats[j], threats[j+1] = threats[j+1], threats[j]
			}
		}
	}
}

// Import stridelm categories for enrichment
func getAllCategories() map[stridelm.Category]struct {
	DetectionStrategies []string
} {
	// Simplified version - real implementation would import from stridelm package
	return map[stridelm.Category]struct {
		DetectionStrategies []string
	}{
		stridelm.Spoofing: {
			DetectionStrategies: []string{
				"Monitor authentication failures",
				"Track credential usage patterns",
				"Validate token integrity",
			},
		},
	}
}
