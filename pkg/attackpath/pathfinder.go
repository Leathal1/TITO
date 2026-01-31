package attackpath

import (
	"container/heap"
	"fmt"
	"math"
)

// PathFinder finds attack paths through the graph
type PathFinder struct {
	graph *AttackGraph
}

// NewPathFinder creates a new path finder
func NewPathFinder(graph *AttackGraph) *PathFinder {
	return &PathFinder{graph: graph}
}

// FindAllPaths finds all paths from entry points to crown jewels with depth limiting
func (pf *PathFinder) FindAllPaths(maxDepth int) []AttackPath {
	paths := make([]AttackPath, 0)

	for _, entryID := range pf.graph.EntryPoints {
		for _, targetID := range pf.graph.CrownJewels {
			// Skip if entry point is the same as target
			if entryID == targetID {
				continue
			}

			// Find all paths using DFS
			foundPaths := pf.dfsAllPaths(entryID, targetID, maxDepth)
			paths = append(paths, foundPaths...)
		}
	}

	return paths
}

// FindShortestPaths finds the shortest (easiest for attacker) paths using Dijkstra
func (pf *PathFinder) FindShortestPaths() []AttackPath {
	paths := make([]AttackPath, 0)

	for _, entryID := range pf.graph.EntryPoints {
		for _, targetID := range pf.graph.CrownJewels {
			if entryID == targetID {
				continue
			}

			path := pf.dijkstraShortestPath(entryID, targetID)
			if path != nil {
				paths = append(paths, *path)
			}
		}
	}

	return paths
}

// FindCriticalPaths finds the N most dangerous paths by composite risk score
func (pf *PathFinder) FindCriticalPaths(topN int) []AttackPath {
	// First find all paths with reasonable depth
	allPaths := pf.FindAllPaths(6) // Max 6 hops

	// Score all paths
	scorer := NewScorer(pf.graph)
	for i := range allPaths {
		allPaths[i].CompositeRisk = scorer.ScorePath(allPaths[i].Steps)
	}

	// Rank and return top N
	ranked := RankPaths(allPaths)
	if len(ranked) > topN {
		return ranked[:topN]
	}
	return ranked
}

// dfsAllPaths performs depth-first search to find all paths
func (pf *PathFinder) dfsAllPaths(start, target string, maxDepth int) []AttackPath {
	paths := make([]AttackPath, 0)
	visited := make(map[string]bool)
	currentPath := make([]AttackStep, 0)

	pf.dfsRecursive(start, target, visited, currentPath, &paths, 0, maxDepth)

	return paths
}

// dfsRecursive is the recursive DFS helper
func (pf *PathFinder) dfsRecursive(current, target string, visited map[string]bool, 
	currentPath []AttackStep, paths *[]AttackPath, depth, maxDepth int) {
	
	// Depth limit check
	if depth > maxDepth {
		return
	}

	// Mark current as visited
	visited[current] = true
	defer func() { visited[current] = false }()

	// If we reached the target, save this path
	if current == target {
		if len(currentPath) > 0 {
			path := pf.buildAttackPath(currentPath, current)
			*paths = append(*paths, path)
		}
		return
	}

	// Explore neighbors
	for _, edge := range pf.graph.Edges {
		if edge.Source == current && !visited[edge.Target] {
			// Create attack step
			step := AttackStep{
				FromNode:    edge.Source,
				ToNode:      edge.Target,
				Technique:   edge.Technique,
				Difficulty:  edge.Difficulty,
				MitreID:     edge.MitreID,
				Description: fmt.Sprintf("Move from %s to %s via %s", 
					pf.graph.Nodes[edge.Source].Label,
					pf.graph.Nodes[edge.Target].Label,
					edge.Technique),
			}

			// Add to current path and recurse
			newPath := append(currentPath, step)
			pf.dfsRecursive(edge.Target, target, visited, newPath, paths, depth+1, maxDepth)
		}
	}
}

// dijkstraShortestPath finds the shortest path using Dijkstra's algorithm
func (pf *PathFinder) dijkstraShortestPath(start, target string) *AttackPath {
	// Distance map (accumulated difficulty)
	dist := make(map[string]float64)
	prev := make(map[string]*AttackEdge)
	
	// Initialize distances
	for nodeID := range pf.graph.Nodes {
		dist[nodeID] = math.Inf(1)
	}
	dist[start] = 0

	// Priority queue
	pq := &priorityQueue{}
	heap.Init(pq)
	heap.Push(pq, &item{nodeID: start, priority: 0})

	visited := make(map[string]bool)

	for pq.Len() > 0 {
		current := heap.Pop(pq).(*item)
		currentID := current.nodeID

		if visited[currentID] {
			continue
		}
		visited[currentID] = true

		// Found target
		if currentID == target {
			return pf.reconstructPath(start, target, prev)
		}

		// Explore neighbors
		for _, edge := range pf.graph.Edges {
			if edge.Source == currentID {
				alt := dist[currentID] + edge.Difficulty
				if alt < dist[edge.Target] {
					dist[edge.Target] = alt
					prev[edge.Target] = edge
					heap.Push(pq, &item{nodeID: edge.Target, priority: alt})
				}
			}
		}
	}

	return nil // No path found
}

// reconstructPath rebuilds the attack path from Dijkstra's previous map
func (pf *PathFinder) reconstructPath(start, target string, prev map[string]*AttackEdge) *AttackPath {
	steps := make([]AttackStep, 0)
	current := target

	// Walk backwards from target to start
	for current != start {
		edge := prev[current]
		if edge == nil {
			return nil
		}

		step := AttackStep{
			FromNode:    edge.Source,
			ToNode:      edge.Target,
			Technique:   edge.Technique,
			Difficulty:  edge.Difficulty,
			MitreID:     edge.MitreID,
			Description: fmt.Sprintf("Move from %s to %s via %s",
				pf.graph.Nodes[edge.Source].Label,
				pf.graph.Nodes[edge.Target].Label,
				edge.Technique),
		}

		steps = append([]AttackStep{step}, steps...) // Prepend
		current = edge.Source
	}

	return &AttackPath{
		ID:         fmt.Sprintf("path_%s_to_%s", start, target),
		EntryPoint: start,
		Target:     target,
		Steps:      steps,
	}
}

// buildAttackPath creates an AttackPath from a sequence of steps
func (pf *PathFinder) buildAttackPath(steps []AttackStep, target string) AttackPath {
	entryPoint := ""
	if len(steps) > 0 {
		entryPoint = steps[0].FromNode
	}

	// Calculate total difficulty (product of individual difficulties)
	totalDifficulty := 1.0
	for _, step := range steps {
		totalDifficulty *= step.Difficulty
	}

	return AttackPath{
		ID:              fmt.Sprintf("path_%s_to_%s_%d", entryPoint, target, len(steps)),
		EntryPoint:      entryPoint,
		Target:          target,
		Steps:           steps,
		TotalDifficulty: totalDifficulty,
	}
}

// Priority queue implementation for Dijkstra's algorithm
type item struct {
	nodeID   string
	priority float64
	index    int
}

type priorityQueue []*item

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	return pq[i].priority < pq[j].priority
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *priorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*item)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[0 : n-1]
	return item
}
