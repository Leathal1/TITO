package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Leathal1/TITO/pkg/attackpath"
	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/scan"
	"github.com/Leathal1/TITO/pkg/scanner"
)

// ComputeDiff compares two scan results and returns the differences
func ComputeDiff(base, head *scan.ScanResult) *DiffResult {
	diff := &DiffResult{
		Base:           base,
		Head:           head,
		AddedAssets:    make([]scanner.Asset, 0),
		RemovedAssets:  make([]scanner.Asset, 0),
		ModifiedAssets: make([]AssetDiff, 0),
		AddedThreats:   make([]*models.Threat, 0),
		RemovedThreats: make([]*models.Threat, 0),
		AddedFlows:     make([]scanner.DataFlow, 0),
		RemovedFlows:   make([]scanner.DataFlow, 0),
		AddedPaths:     make([]attackpath.AttackPath, 0),
		RemovedPaths:   make([]attackpath.AttackPath, 0),
		AddedDeps:      make([]scanner.Dependency, 0),
		RemovedDeps:    make([]scanner.Dependency, 0),
		UpdatedDeps:    make([]DependencyDiff, 0),
	}

	// Compare assets
	diffAssets(base.Assets, head.Assets, diff)

	// Compare threats
	diffThreats(base.Threats, head.Threats, diff)

	// Compare data flows
	diffDataFlows(base.DataFlows, head.DataFlows, diff)

	// Compare attack paths
	diffAttackPaths(base.AttackPaths, head.AttackPaths, diff)

	// Compare dependencies
	diffDependencies(base.Dependencies, head.Dependencies, diff)

	// Calculate risk delta
	diff.RiskDelta = calculateRiskDelta(base, head)

	// Calculate summary
	diff.Summary = calculateSummary(diff)

	return diff
}

// diffAssets compares assets between base and head
func diffAssets(baseAssets, headAssets []scanner.Asset, diff *DiffResult) {
	baseMap := make(map[string]scanner.Asset)
	headMap := make(map[string]scanner.Asset)

	// Build maps using composite key: Type:Name@File
	for _, asset := range baseAssets {
		key := assetKey(asset)
		baseMap[key] = asset
	}
	for _, asset := range headAssets {
		key := assetKey(asset)
		headMap[key] = asset
	}

	// Find added and modified
	for key, headAsset := range headMap {
		if baseAsset, exists := baseMap[key]; exists {
			// Check if modified
			changes := compareAssets(baseAsset, headAsset)
			if len(changes) > 0 {
				diff.ModifiedAssets = append(diff.ModifiedAssets, AssetDiff{
					Before:  baseAsset,
					After:   headAsset,
					Changes: changes,
				})
			}
		} else {
			// New asset
			diff.AddedAssets = append(diff.AddedAssets, headAsset)
		}
	}

	// Find removed
	for key, baseAsset := range baseMap {
		if _, exists := headMap[key]; !exists {
			diff.RemovedAssets = append(diff.RemovedAssets, baseAsset)
		}
	}

	// Sort for determinism
	sortAssets(diff.AddedAssets)
	sortAssets(diff.RemovedAssets)
	sortAssetDiffs(diff.ModifiedAssets)
}

// diffThreats compares threats between base and head
func diffThreats(baseThreats, headThreats []*models.Threat, diff *DiffResult) {
	baseMap := make(map[string]*models.Threat)
	headMap := make(map[string]*models.Threat)

	// Build maps using Title:Severity as key (threats don't have stable IDs)
	for _, threat := range baseThreats {
		key := threatKey(threat)
		baseMap[key] = threat
	}
	for _, threat := range headThreats {
		key := threatKey(threat)
		headMap[key] = threat
	}

	// Find added
	for key, headThreat := range headMap {
		if _, exists := baseMap[key]; !exists {
			diff.AddedThreats = append(diff.AddedThreats, headThreat)
		}
	}

	// Find removed
	for key, baseThreat := range baseMap {
		if _, exists := headMap[key]; !exists {
			diff.RemovedThreats = append(diff.RemovedThreats, baseThreat)
		}
	}

	// Sort for determinism
	sortThreats(diff.AddedThreats)
	sortThreats(diff.RemovedThreats)
}

// diffDataFlows compares data flows between base and head
func diffDataFlows(baseFlows, headFlows []scanner.DataFlow, diff *DiffResult) {
	baseMap := make(map[string]scanner.DataFlow)
	headMap := make(map[string]scanner.DataFlow)

	// Build maps using Source.File:Destination.File:DataType as key
	for _, flow := range baseFlows {
		key := dataFlowKey(flow)
		baseMap[key] = flow
	}
	for _, flow := range headFlows {
		key := dataFlowKey(flow)
		headMap[key] = flow
	}

	// Find added
	for key, headFlow := range headMap {
		if _, exists := baseMap[key]; !exists {
			diff.AddedFlows = append(diff.AddedFlows, headFlow)
		}
	}

	// Find removed
	for key, baseFlow := range baseMap {
		if _, exists := headMap[key]; !exists {
			diff.RemovedFlows = append(diff.RemovedFlows, baseFlow)
		}
	}

	// Sort for determinism
	sortDataFlows(diff.AddedFlows)
	sortDataFlows(diff.RemovedFlows)
}

// diffAttackPaths compares attack paths between base and head
func diffAttackPaths(basePaths, headPaths []attackpath.AttackPath, diff *DiffResult) {
	baseMap := make(map[string]attackpath.AttackPath)
	headMap := make(map[string]attackpath.AttackPath)

	// Build maps using EntryPoint:Target as key
	for _, path := range basePaths {
		key := attackPathKey(path)
		baseMap[key] = path
	}
	for _, path := range headPaths {
		key := attackPathKey(path)
		headMap[key] = path
	}

	// Find added
	for key, headPath := range headMap {
		if _, exists := baseMap[key]; !exists {
			diff.AddedPaths = append(diff.AddedPaths, headPath)
		}
	}

	// Find removed
	for key, basePath := range baseMap {
		if _, exists := headMap[key]; !exists {
			diff.RemovedPaths = append(diff.RemovedPaths, basePath)
		}
	}

	// Sort for determinism
	sortAttackPaths(diff.AddedPaths)
	sortAttackPaths(diff.RemovedPaths)
}

// diffDependencies compares dependencies between base and head
func diffDependencies(baseDeps, headDeps []scanner.Dependency, diff *DiffResult) {
	baseMap := make(map[string]scanner.Dependency)
	headMap := make(map[string]scanner.Dependency)

	// Build maps using Name as key
	for _, dep := range baseDeps {
		baseMap[dep.Name] = dep
	}
	for _, dep := range headDeps {
		headMap[dep.Name] = dep
	}

	// Find added and updated
	for name, headDep := range headMap {
		if baseDep, exists := baseMap[name]; exists {
			// Check version change
			if baseDep.Version != headDep.Version {
				diff.UpdatedDeps = append(diff.UpdatedDeps, DependencyDiff{
					Name:       name,
					OldVersion: baseDep.Version,
					NewVersion: headDep.Version,
				})
			}
		} else {
			// New dependency
			diff.AddedDeps = append(diff.AddedDeps, headDep)
		}
	}

	// Find removed
	for name, baseDep := range baseMap {
		if _, exists := headMap[name]; !exists {
			diff.RemovedDeps = append(diff.RemovedDeps, baseDep)
		}
	}

	// Sort for determinism
	sortDependencies(diff.AddedDeps)
	sortDependencies(diff.RemovedDeps)
	sortDependencyDiffs(diff.UpdatedDeps)
}

// calculateRiskDelta computes the change in risk metrics
func calculateRiskDelta(base, head *scan.ScanResult) RiskDelta {
	delta := RiskDelta{
		BaseMaxRisk:      base.Stats.MaxRiskScore,
		HeadMaxRisk:      head.Stats.MaxRiskScore,
		BaseAvgRisk:      base.Stats.AvgRiskScore,
		HeadAvgRisk:      head.Stats.AvgRiskScore,
		ThreatCountDelta: head.Stats.TotalThreats - base.Stats.TotalThreats,
	}

	// Determine risk direction
	if head.Stats.MaxRiskScore > base.Stats.MaxRiskScore {
		delta.RiskDirection = "increased"
	} else if head.Stats.MaxRiskScore < base.Stats.MaxRiskScore {
		delta.RiskDirection = "decreased"
	} else {
		delta.RiskDirection = "unchanged"
	}

	return delta
}

// calculateSummary computes summary statistics
func calculateSummary(diff *DiffResult) DiffSummary {
	summary := DiffSummary{
		TotalChanges:    len(diff.AddedAssets) + len(diff.RemovedAssets) + len(diff.ModifiedAssets) +
			len(diff.AddedThreats) + len(diff.RemovedThreats) +
			len(diff.AddedFlows) + len(diff.RemovedFlows) +
			len(diff.AddedPaths) + len(diff.RemovedPaths) +
			len(diff.AddedDeps) + len(diff.RemovedDeps) + len(diff.UpdatedDeps),
		NewHighSeverity: 0,
		ResolvedThreats: len(diff.RemovedThreats),
		NewAttackPaths:  len(diff.AddedPaths),
	}

	// Count new high-severity threats
	for _, threat := range diff.AddedThreats {
		if threat.Severity == models.SeverityCritical || threat.Severity == models.SeverityHigh {
			summary.NewHighSeverity++
		}
	}

	return summary
}

// Key generation functions

func assetKey(asset scanner.Asset) string {
	return fmt.Sprintf("%s:%s@%s", asset.Type, asset.Name, asset.Location.File)
}

func threatKey(threat *models.Threat) string {
	return fmt.Sprintf("%s:%s", threat.Title, threat.Severity)
}

func dataFlowKey(flow scanner.DataFlow) string {
	return fmt.Sprintf("%s:%s:%s", flow.Source.File, flow.Destination.File, flow.DataType)
}

func attackPathKey(path attackpath.AttackPath) string {
	return fmt.Sprintf("%s:%s", path.EntryPoint, path.Target)
}

// Asset comparison
func compareAssets(before, after scanner.Asset) []string {
	changes := make([]string, 0)

	if before.Sensitive != after.Sensitive {
		changes = append(changes, fmt.Sprintf("sensitivity changed: %v → %v", before.Sensitive, after.Sensitive))
	}
	if before.Exposed != after.Exposed {
		changes = append(changes, fmt.Sprintf("exposure changed: %v → %v", before.Exposed, after.Exposed))
	}
	if before.Description != after.Description {
		changes = append(changes, "description changed")
	}
	if !equalStringSlices(before.Tags, after.Tags) {
		changes = append(changes, "tags changed")
	}

	return changes
}

// Sorting functions for determinism

func sortAssets(assets []scanner.Asset) {
	sort.Slice(assets, func(i, j int) bool {
		return assetKey(assets[i]) < assetKey(assets[j])
	})
}

func sortAssetDiffs(diffs []AssetDiff) {
	sort.Slice(diffs, func(i, j int) bool {
		return assetKey(diffs[i].After) < assetKey(diffs[j].After)
	})
}

func sortThreats(threats []*models.Threat) {
	sort.Slice(threats, func(i, j int) bool {
		// Sort by severity (critical first), then title
		if threats[i].Severity != threats[j].Severity {
			return threats[i].Severity.Score() > threats[j].Severity.Score()
		}
		return threats[i].Title < threats[j].Title
	})
}

func sortDataFlows(flows []scanner.DataFlow) {
	sort.Slice(flows, func(i, j int) bool {
		return dataFlowKey(flows[i]) < dataFlowKey(flows[j])
	})
}

func sortAttackPaths(paths []attackpath.AttackPath) {
	sort.Slice(paths, func(i, j int) bool {
		// Sort by composite risk (highest first)
		if paths[i].CompositeRisk != paths[j].CompositeRisk {
			return paths[i].CompositeRisk > paths[j].CompositeRisk
		}
		return attackPathKey(paths[i]) < attackPathKey(paths[j])
	})
}

func sortDependencies(deps []scanner.Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Name < deps[j].Name
	})
}

func sortDependencyDiffs(diffs []DependencyDiff) {
	sort.Slice(diffs, func(i, j int) bool {
		return diffs[i].Name < diffs[j].Name
	})
}

// Helper functions

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))
	copy(aCopy, a)
	copy(bCopy, b)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if aCopy[i] != bCopy[i] {
			return false
		}
	}
	return true
}

// NormalizeForComparison removes fields that vary between identical scans
func NormalizeForComparison(result *scan.ScanResult) {
	// Reset timestamp
	result.Timestamp = result.Timestamp.UTC().Truncate(0)

	// Reset auto-generated IDs that might vary
	for i := range result.Assets {
		// Keep ID structure but make deterministic
		parts := strings.Split(result.Assets[i].ID, "-")
		if len(parts) > 0 {
			// Keep type and file, normalize line-based suffix
			result.Assets[i].ID = assetKey(result.Assets[i])
		}
	}

	for i := range result.DataFlows {
		result.DataFlows[i].ID = dataFlowKey(result.DataFlows[i])
	}
}
