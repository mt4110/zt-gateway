package engine

// Result represents the outcome of a scan on a single file.
type Result struct {
	FilePath string
	Scanner  string   // e.g., "ClamAV", "YARA"
	Status   Status   // OK, Infected, Error, Skipped
	Message  string   // Threat name or error details
}

type Status int

const (
	StatusClean Status = iota
	StatusInfected
	StatusError
	StatusSkipped
)

func (s Status) String() string {
	switch s {
	case StatusClean:
		return "CLEAN"
	case StatusInfected:
		return "INFECTED"
	case StatusError:
		return "ERROR"
	case StatusSkipped:
		return "SKIPPED"
	default:
		return "UNKNOWN"
	}
}

// Scanner is the interface that all scanning engines must implement.
type Scanner interface {
	// Name returns the display name of the scanner.
	Name() string

	// ScanFile scans a single file and returns the result.
	// Context cancellation/timeout should be handled by the implementation if possible.
	ScanFile(path string) (*Result, error)
	
	// Available checks if the external tool is installed and ready.
	Available() bool
	
	// Version returns the version of the underlying tool.
	Version() string
}
