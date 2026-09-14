package engine

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
)

type Engine struct {
	Scanners []Scanner
}

func NewEngine(scanners ...Scanner) *Engine {
	return &Engine{
		Scanners: scanners,
	}
}

// StartScan walks the directory and scans each file with all enabled scanners.
// It returns a channel of results.
// concurrency: Number of parallel workers (0 = auto/default).
func (e *Engine) StartScan(ctx context.Context, root string, concurrency int) (<-chan Result, <-chan error) {
	results := make(chan Result)
	errs := make(chan error)

	if concurrency <= 0 {
		concurrency = 1
	}

	go func() {
		defer close(results)
		defer close(errs)

		var wg sync.WaitGroup
		// Semaphore to limit concurrency
		sem := make(chan struct{}, concurrency) 

		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				errs <- err
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" || d.Name() == ".cache" {
					return filepath.SkipDir
				}
				return nil
			}

			// Wait for semaphore
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}

			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				defer func() { <-sem }()
				e.processFile(p, results)
			}(path)

			return nil
		})

		if err != nil {
			errs <- fmt.Errorf("walk error: %w", err)
		}

		wg.Wait()
	}()

	return results, errs
}

func (e *Engine) processFile(path string, results chan<- Result) {
	for _, s := range e.Scanners {
		if !s.Available() {
			continue
		}
		
		res, err := s.ScanFile(path)
		if err != nil {
			results <- Result{
				FilePath: path,
				Scanner:  s.Name(),
				Status:   StatusError,
				Message:  err.Error(),
			}
		} else {
			results <- *res
		}
		
		// If infected, stop other scanners for this file
		if res != nil && res.Status == StatusInfected {
			break
		}
	}
}
