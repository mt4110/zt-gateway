package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Metadata structure for the artifact
type Metadata struct {
	OriginalFilename string    `json:"original_filename"`
	Timestamp        time.Time `json:"timestamp"`
	Sender           string    `json:"sender"`
	PayloadHash      string    `json:"payload_hash"`
	ToolchainHash    string    `json:"toolchain_hash"`
	KeyID            string    `json:"key_id"` // Identified which key signed this
}

func main() {
	packCmd := flag.NewFlagSet("pack", flag.ExitOnError)
	
	if len(os.Args) < 2 {
		fmt.Println("Usage: secure-pack <command> [args]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "pack":
		packCmd.Parse(os.Args[2:])
		args := packCmd.Args()
		if len(args) < 2 {
			fmt.Println("Usage: secure-pack pack <input_file> <output_dir>")
			os.Exit(1)
		}
		inputFile := args[0]
		outputDir := args[1]
		if err := runPack(inputFile, outputDir); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func runPack(inputFile, outputDir string) error {
	// 1. Create artifact directory (artifact.zp)
	artifactName := "artifact.zp"
	artifactPath := filepath.Join(outputDir, artifactName)
	if err := os.MkdirAll(artifactPath, 0755); err != nil {
		return fmt.Errorf("failed to create artifact dir: %w", err)
	}

	// 2. Read input file and calculate hash (simulating processing)
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}
	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])

    // Load Keys (Env vars for now)
    aesKeyHex := os.Getenv("ZT_KEY_AES")
    edPrivKeyHex := os.Getenv("ZT_KEY_ED25519")

    // Default keys (DEV ONLY - WARN IN PRODUCTION)
    if aesKeyHex == "" {
        // 32 bytes = 64 hex chars
        aesKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" 
    }
    if edPrivKeyHex == "" {
        // Ed25519 Seed (32 bytes) or Private Key (64 bytes). 
        // Let's use Seed for simplicity if generating. or a fixed stub private key for dev.
        // This is a dummy seed.
        edPrivKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    }

	// 3. Encrypt (AES-256-GCM)
    aesKey, _ := hex.DecodeString(aesKeyHex)
	ciphertext, nonce, err := encryptAESGCM(data, aesKey)
    if err != nil {
        return fmt.Errorf("encryption failed: %w", err)
    }

	encPath := filepath.Join(artifactPath, "payload.enc")
    // Store Nonce + Ciphertext ? Or just ciphertext and store nonce separately?
    // Standard practice: Nonce prepended to ciphertext.
    finalPayload := append(nonce, ciphertext...)
	if err := os.WriteFile(encPath, finalPayload, 0644); err != nil {
		return fmt.Errorf("failed to write payload: %w", err)
	}

	// 4. Create Metadata
	meta := Metadata{
		OriginalFilename: filepath.Base(inputFile),
		Timestamp:        time.Now().UTC(),
		Sender:           os.Getenv("USER"),
		PayloadHash:      hashStr,
		ToolchainHash:    "nix-hash-stub",
        KeyID:            "dev-key-01",
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(artifactPath, "metadata.json"), metaBytes, 0644); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// 5. Sign (Ed25519)
    // Sign the HASH of the original data (not the encrypted data, usually sign plaintext hash/metadata)
    // Spec says: "payload.sig" -> implies signing the payload? Or the hash?
    // Let's sign the Payload Hash to verify integrity of the original file.
    privKeySeed, _ := hex.DecodeString(edPrivKeyHex)
    privKey := ed25519.NewKeyFromSeed(privKeySeed)
    
    // We sign the Metadata content (which includes the hash) OR just the hash.
    // Signing the hash corresponds to "I certify this content".
    signature := ed25519.Sign(privKey, []byte(hashStr))
    sigHex := hex.EncodeToString(signature)
    
	if err := os.WriteFile(filepath.Join(artifactPath, "payload.sig"), []byte(sigHex), 0644); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}
    
    // Write Public Key Fingerprint (stub logic for now, derived from priv)
    // pubKey := privKey.Public().(ed25519.PublicKey)
    if err := os.WriteFile(filepath.Join(artifactPath, "signer.fp"), []byte("dev-key-01-fingerprint"), 0644); err != nil {
        return fmt.Errorf("failed to write signer fingerprint: %w", err)
    }
    
    // 6. Lock file
    if err := os.WriteFile(filepath.Join(artifactPath, "toolchain.lock"), []byte("toolchain-lock-content"), 0644); err != nil {
        return fmt.Errorf("failed to write toolchain lock: %w", err)
    }

	fmt.Printf("Artifact created at: %s\n", artifactPath)
	return nil
}

func encryptAESGCM(plaintext []byte, key []byte) ([]byte, []byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, nil, err
    }

    // Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
    nonce := make([]byte, 12)
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, nil, err
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, nil, err
    }

    ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
    return ciphertext, nonce, nil
}
