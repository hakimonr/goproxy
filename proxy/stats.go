package proxy

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type EndpointStats struct {
	Path            string
	SuccessCount    int64
	FailureCount    int64
	TotalTime       time.Duration
	MinTime         time.Duration
	MaxTime         time.Duration
	BytesSent       int64
	BytesReceived   int64
	StatusCodes     map[int]int64
}

type AdvancedStats struct {
	endpoints map[string]*EndpointStats
	mu        sync.RWMutex
}

func NewAdvancedStats() *AdvancedStats {
	return &AdvancedStats{
		endpoints: make(map[string]*EndpointStats),
	}
}

func (s *AdvancedStats) RecordRequest(path string, statusCode int, duration time.Duration, bytesSent, bytesReceived int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats, exists := s.endpoints[path]
	if !exists {
		stats = &EndpointStats{
			Path:        path,
			MinTime:     duration,
			MaxTime:     duration,
			StatusCodes: make(map[int]int64),
		}
		s.endpoints[path] = stats
	}

	// Update counts
	if statusCode >= 200 && statusCode < 400 {
		stats.SuccessCount++
	} else {
		stats.FailureCount++
	}

	// Update timing
	stats.TotalTime += duration
	if duration < stats.MinTime {
		stats.MinTime = duration
	}
	if duration > stats.MaxTime {
		stats.MaxTime = duration
	}

	// Update bandwidth
	stats.BytesSent += bytesSent
	stats.BytesReceived += bytesReceived

	// Update status codes
	stats.StatusCodes[statusCode]++
}

func (s *AdvancedStats) GetTopSlowEndpoints(limit int) []*EndpointStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	endpoints := make([]*EndpointStats, 0, len(s.endpoints))
	for _, stats := range s.endpoints {
		endpoints = append(endpoints, stats)
	}

	// Sort by average time (descending)
	sort.Slice(endpoints, func(i, j int) bool {
		avgI := endpoints[i].TotalTime / time.Duration(endpoints[i].SuccessCount+endpoints[i].FailureCount)
		avgJ := endpoints[j].TotalTime / time.Duration(endpoints[j].SuccessCount+endpoints[j].FailureCount)
		return avgI > avgJ
	})

	if len(endpoints) > limit {
		endpoints = endpoints[:limit]
	}

	return endpoints
}

func (s *AdvancedStats) GetSummary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var totalSuccess, totalFailure int64
	var totalBytes int64
	errorDist := make(map[int]int64)

	for _, stats := range s.endpoints {
		totalSuccess += stats.SuccessCount
		totalFailure += stats.FailureCount
		totalBytes += stats.BytesReceived
		for code, count := range stats.StatusCodes {
			if code >= 400 {
				errorDist[code] += count
			}
		}
	}

	total := totalSuccess + totalFailure
	successRate := float64(0)
	if total > 0 {
		successRate = float64(totalSuccess) / float64(total) * 100
	}

	summary := fmt.Sprintf("\n=== Advanced Statistics ===\n")
	summary += fmt.Sprintf("Total Requests: %d\n", total)
	summary += fmt.Sprintf("Success Rate: %.2f%% (%d/%d)\n", successRate, totalSuccess, total)
	summary += fmt.Sprintf("Failure Rate: %.2f%% (%d/%d)\n", 100-successRate, totalFailure, total)
	summary += fmt.Sprintf("Total Bandwidth: %.2f MB\n", float64(totalBytes)/(1024*1024))

	if len(errorDist) > 0 {
		summary += fmt.Sprintf("\nError Distribution:\n")
		for code, count := range errorDist {
			summary += fmt.Sprintf("  %d: %d requests\n", code, count)
		}
	}

	topSlow := s.GetTopSlowEndpoints(5)
	if len(topSlow) > 0 {
		summary += fmt.Sprintf("\nTop 5 Slowest Endpoints:\n")
		for i, stats := range topSlow {
			total := stats.SuccessCount + stats.FailureCount
			avgTime := stats.TotalTime / time.Duration(total)
			summary += fmt.Sprintf("  %d. %s - Avg: %dms (Min: %dms, Max: %dms)\n",
				i+1, stats.Path, avgTime.Milliseconds(), stats.MinTime.Milliseconds(), stats.MaxTime.Milliseconds())
		}
	}

	return summary
}
