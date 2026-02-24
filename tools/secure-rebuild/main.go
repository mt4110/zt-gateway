package main

import (
	"flag"
	"fmt"
    "image"
    _ "image/jpeg"
    "image/jpeg"
    _ "image/png"
    "image/png"
	"io"
	"os"
	"path/filepath"
)

func main() {
	rebuildCmd := flag.NewFlagSet("rebuild", flag.ExitOnError)
	
	if len(os.Args) < 2 {
		fmt.Println("Usage: secure-rebuild <command> [args]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "rebuild":
		rebuildCmd.Parse(os.Args[2:])
		args := rebuildCmd.Args()
		if len(args) < 2 {
			fmt.Println("Usage: secure-rebuild rebuild <input_file> <output_file>")
			os.Exit(1)
		}
		inputFile := args[0]
		outputFile := args[1]
		if err := runRebuild(inputFile, outputFile); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func runRebuild(inputFile, outputFile string) error {
    // 1. Identify File Type (Stub: Just extension for now)
    ext := filepath.Ext(inputFile)

    fmt.Printf("[Rebuild] Processing %s (Type: %s)\n", inputFile, ext)

    // 2. Select Sanitizer
    switch ext {
    case ".jpg", ".jpeg", ".png":
        return sanitizeImage(inputFile, outputFile)
    default:
        // Default: Pass through (Copy) if no sanitizer defined? 
        // Or fail safe? For Day 3, let's copy with a warning if allowed by policy,
        // but strictly speaking CDR should FAIL if it can't rebuild.
        // Let's implement a simple copy "dummy sanitizer" for non-supported types for now,
        // so we don't block existing flows (txt, pdf) until we have rebuilders for them.
        fmt.Println("[Rebuild] No specific sanitizer found. Performing identity copy.")
        return copyFile(inputFile, outputFile)
    }
}

func sanitizeImage(inputFile, outputFile string) error {
    fmt.Println("[Rebuild] Sanitizing Image (Stripping Metadata)...")
    
    // Open input
    f, err := os.Open(inputFile)
    if err != nil {
        return err
    }
    defer f.Close()
    
    // Decode image (this ignores metadata usually)
    // Note: This relies on image/jpeg and image/png being imported for side-effects
    img, format, err := image.Decode(f)
    if err != nil {
        // If we can't decode, it might be corrupted or valid but unsupported.
        // Fail closed for "Rebuild" philosophy -> Can't rebuild = Can't verify safety.
        return fmt.Errorf("failed to decode image: %w", err)
    }
    
    fmt.Printf("[Rebuild] Decoded %s image. Re-encoding stripping metadata...\n", format)
    
    // Create output
    out, err := os.Create(outputFile)
    if err != nil {
        return err
    }
    defer out.Close()
    
    // Re-encode
    // This process naturally strips Exif because Go's standard library 
    // encoders do not preserve metadata from the Decode unless explicitly handled.
    switch format {
    case "jpeg":
        return jpeg.Encode(out, img, &jpeg.Options{Quality: 85})
    case "png":
        return png.Encode(out, img)
    default:
        return fmt.Errorf("unsupported image format for re-encoding: %s", format)
    }
}

func copyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	if _, err := io.Copy(destination, source); err != nil {
		return err
	}
	return nil
}
