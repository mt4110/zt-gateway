package sysinfo

import (
	"fmt"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

const (
	// SamplingInterval determines how often we check CPU usage.
	// Recommended: 500ms for human-readable stability.
	// Lower values (e.g. 100ms) increase jitter and overhead.
	SamplingInterval = 500 * time.Millisecond

	// ThrottleThreshold is the percentage of CPU/RAM usage above which
	// we force the scanner to reduce concurrency to minimum (1).
	// Recommended: 85.0 (Leave some headroom for OS).
	ThrottleThreshold = 85.0
)

type SystemStats struct {
	CPUPercent float64
	MemPercent float64
	MemUsed    uint64
	MemTotal   uint64
	NumCPU     int
}

// GetStats returns current system resource usage.
// Calling CPUPercent needs a duration, so this function might block briefly (SamplingInterval).
// For TUI, it's better to run this in a goroutine/ticker.
func GetStats() (*SystemStats, error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	// Use defined constant duration
	c, err := cpu.Percent(SamplingInterval, false)
	if err != nil {
		return nil, err
	}

	cpuUsage := 0.0
	if len(c) > 0 {
		cpuUsage = c[0]
	}

	return &SystemStats{
		CPUPercent: cpuUsage,
		MemPercent: v.UsedPercent,
		MemUsed:    v.Used,
		MemTotal:   v.Total,
		NumCPU:     runtime.NumCPU(),
	}, nil
}

// CalculateConcurrency returns a recommended worker count (1-100)
// based on current CPU/Mem load.
func CalculateConcurrency(stats *SystemStats) int {
	// Check against defined constant threshold
	if stats.CPUPercent > ThrottleThreshold || stats.MemPercent > ThrottleThreshold {
		return 1
	}
	
	// Default: Use all cores if healthy
	n := stats.NumCPU
	if n < 1 {
		n = 1
	}
	
	return n
}

func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return "0 B"
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return calculateBytesString(float64(bytes)/float64(div), exp)
}

func calculateBytesString(val float64, exp int) string {
	suffix := "KMGTPE"[exp]
	// Using standard formatting for readability
	return fmt.Sprintf("%.1f %cB", val, suffix)
}
