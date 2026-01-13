package collectors

import (
	"context"
	"time"

	"github.com/Leathal1/TITO/pkg/models"
)

// Collector is the interface that all threat intelligence collectors must implement
// Every collector must know its source, fetch raw data, and transform it into Threat objects
type Collector interface {
	// Name returns the human-readable name of the intelligence source
	Name() string

	// Collect performs the collection workflow and returns threats
	Collect(ctx context.Context) ([]*models.Threat, error)

	// Status returns the current status of the collector
	Status() CollectorStatus
}

// CollectorStatus represents the status of a collector
type CollectorStatus struct {
	Name      string    `json:"name"`
	Source    string    `json:"source"`
	LastRun   time.Time `json:"last_run,omitempty"`
	Errors    []string  `json:"errors,omitempty"`
	ErrorCount int      `json:"error_count"`
}

// ScheduledCollector is a collector that runs on a schedule
type ScheduledCollector interface {
	Collector

	// Interval returns how often the collector should run
	Interval() time.Duration

	// ShouldRun checks if enough time has passed since last run
	ShouldRun() bool
}

// BaseCollector provides common functionality for collectors
type BaseCollector struct {
	name    string
	lastRun time.Time
	errors  []string
}

// NewBaseCollector creates a new base collector
func NewBaseCollector(name string) *BaseCollector {
	return &BaseCollector{
		name:   name,
		errors: make([]string, 0),
	}
}

// Name returns the collector name
func (bc *BaseCollector) Name() string {
	return bc.name
}

// Status returns the collector status
func (bc *BaseCollector) Status() CollectorStatus {
	return CollectorStatus{
		Name:       bc.name,
		LastRun:    bc.lastRun,
		Errors:     bc.errors,
		ErrorCount: len(bc.errors),
	}
}

// RecordRun records that the collector has run
func (bc *BaseCollector) RecordRun() {
	bc.lastRun = time.Now()
}

// AddError adds an error to the collector's error list
func (bc *BaseCollector) AddError(err error) {
	bc.errors = append(bc.errors, err.Error())
}

// ClearErrors clears the error list
func (bc *BaseCollector) ClearErrors() {
	bc.errors = make([]string, 0)
}
