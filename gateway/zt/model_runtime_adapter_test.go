package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFakeRuntimeAdapterInjectsPlaceholderModelPath(t *testing.T) {
	adapter := fakeModelRuntimeAdapter{}
	model := modelRuntimeModelView{Path: "/tmp/model.gguf", Available: true}
	args, err := adapter.BuildCommandArgs(modelRuntimeContext{}, model, []string{"fake-runtime", "--model", modelRuntimeModelPlaceholder})
	if err != nil {
		t.Fatalf("BuildCommandArgs: %v", err)
	}
	want := []string{"fake-runtime", "--model", "/tmp/model.gguf"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args=%v, want %v", args, want)
	}
}

func TestFakeRuntimeAdapterPreservesArgsWithoutModelPlaceholder(t *testing.T) {
	adapter := fakeModelRuntimeAdapter{}
	args, err := adapter.BuildCommandArgs(modelRuntimeContext{}, modelRuntimeModelView{}, []string{"fake-runtime", "--dry-run"})
	if err != nil {
		t.Fatalf("BuildCommandArgs: %v", err)
	}
	want := []string{"fake-runtime", "--dry-run"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args=%v, want %v", args, want)
	}
}

func TestLlamaCPPAdapterInjectsModelFlagAfterExecutable(t *testing.T) {
	adapter := llamaCPPModelRuntimeAdapter{}
	model := modelRuntimeModelView{Path: "/tmp/model.gguf", Available: true}
	args, err := adapter.BuildCommandArgs(modelRuntimeContext{}, model, []string{"llama-server", "--port", "8080"})
	if err != nil {
		t.Fatalf("BuildCommandArgs: %v", err)
	}
	want := []string{"llama-server", "--model", "/tmp/model.gguf", "--port", "8080"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args=%v, want %v", args, want)
	}
}

func TestLlamaCPPAdapterReplacesExistingModelFlag(t *testing.T) {
	adapter := llamaCPPModelRuntimeAdapter{}
	model := modelRuntimeModelView{Path: "/tmp/model.gguf", Available: true}
	args, err := adapter.BuildCommandArgs(modelRuntimeContext{}, model, []string{"llama-server", "--model", "/tmp/other.gguf", "--ctx-size", "4096"})
	if err != nil {
		t.Fatalf("BuildCommandArgs: %v", err)
	}
	want := []string{"llama-server", "--model", "/tmp/model.gguf", "--ctx-size", "4096"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args=%v, want %v", args, want)
	}
}

func TestLlamaCPPAdapterReplacesModelEqualsFlag(t *testing.T) {
	adapter := llamaCPPModelRuntimeAdapter{}
	model := modelRuntimeModelView{Path: "/tmp/model.gguf", Available: true}
	args, err := adapter.BuildCommandArgs(modelRuntimeContext{}, model, []string{"llama-server", "--model=/tmp/other.gguf"})
	if err != nil {
		t.Fatalf("BuildCommandArgs: %v", err)
	}
	want := []string{"llama-server", "--model=/tmp/model.gguf"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args=%v, want %v", args, want)
	}
}

func TestLlamaCPPAdapterRejectsMissingModelWhenNoExtract(t *testing.T) {
	adapter := llamaCPPModelRuntimeAdapter{}
	_, err := adapter.BuildCommandArgs(modelRuntimeContext{}, modelRuntimeModelView{Path: "/tmp/model.gguf", Available: false}, []string{"llama-server"})
	if err == nil || !strings.Contains(err.Error(), "--no-extract") {
		t.Fatalf("err=%v, want --no-extract model unavailable", err)
	}
}

func TestModelRunPrimaryModelViewFindsDocsArtifact(t *testing.T) {
	workspace := t.TempDir()
	modelDir := filepath.Join(workspace, "model", "docs")
	if err := os.MkdirAll(modelDir, 0700); err != nil {
		t.Fatal(err)
	}
	modelPath := filepath.Join(modelDir, "weights.gguf")
	if err := os.WriteFile(modelPath, []byte("weights"), 0600); err != nil {
		t.Fatal(err)
	}
	view, err := modelRunPrimaryModelView(workspace, modelCapsuleManifestV1{
		Artifacts: []modelManifestArtifact{
			{Path: "weights.gguf", Kind: modelArtifactKindWeight},
		},
	}, true)
	if err != nil {
		t.Fatalf("modelRunPrimaryModelView: %v", err)
	}
	if view.Path != modelPath || !view.Available {
		t.Fatalf("view=%+v, want path=%s available=true", view, modelPath)
	}
}
