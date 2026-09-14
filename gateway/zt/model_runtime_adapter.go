package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

const modelRuntimeModelPlaceholder = "{}"

type modelRuntimeContext struct {
	Workspace string
	Runtime   string
}

type modelRuntimeModelView struct {
	Path      string
	Available bool
}

type modelRuntimeAdapter interface {
	Name() string
	BuildCommandArgs(ctx modelRuntimeContext, model modelRuntimeModelView, args []string) ([]string, error)
}

func modelRuntimeAdapterFor(runtimeName string) (modelRuntimeAdapter, error) {
	switch strings.ToLower(strings.TrimSpace(runtimeName)) {
	case "fake":
		return fakeModelRuntimeAdapter{}, nil
	case "llama.cpp":
		return llamaCPPModelRuntimeAdapter{}, nil
	default:
		return nil, fmt.Errorf("unsupported runtime adapter %q", runtimeName)
	}
}

type fakeModelRuntimeAdapter struct{}

func (fakeModelRuntimeAdapter) Name() string {
	return "fake"
}

func (fakeModelRuntimeAdapter) BuildCommandArgs(_ modelRuntimeContext, model modelRuntimeModelView, args []string) ([]string, error) {
	args = cloneRuntimeArgs(args)
	if len(args) == 0 {
		return args, nil
	}
	return injectRuntimeModelPath(args, model, runtimeModelInjectionOptional)
}

type llamaCPPModelRuntimeAdapter struct{}

func (llamaCPPModelRuntimeAdapter) Name() string {
	return "llama.cpp"
}

func (llamaCPPModelRuntimeAdapter) BuildCommandArgs(_ modelRuntimeContext, model modelRuntimeModelView, args []string) ([]string, error) {
	args = cloneRuntimeArgs(args)
	if len(args) == 0 {
		return nil, fmt.Errorf("llama.cpp runtime requires an executable command")
	}
	return injectRuntimeModelPath(args, model, runtimeModelInjectionRequired)
}

type runtimeModelInjectionMode int

const (
	runtimeModelInjectionOptional runtimeModelInjectionMode = iota
	runtimeModelInjectionRequired
)

func injectRuntimeModelPath(args []string, model modelRuntimeModelView, mode runtimeModelInjectionMode) ([]string, error) {
	if len(args) == 0 {
		return cloneRuntimeArgs(args), nil
	}
	out := cloneRuntimeArgs(args)
	injected := false
	for i := range out {
		if out[i] == modelRuntimeModelPlaceholder {
			if err := requireRuntimeModelPath(model); err != nil {
				return nil, err
			}
			out[i] = model.Path
			injected = true
		}
	}
	for i := 1; i < len(out); i++ {
		switch {
		case out[i] == "--model" || out[i] == "-m":
			if i+1 >= len(out) {
				return nil, fmt.Errorf("%s requires a model path value", out[i])
			}
			if err := requireRuntimeModelPath(model); err != nil {
				return nil, err
			}
			out[i+1] = model.Path
			injected = true
			i++
		case strings.HasPrefix(out[i], "--model="):
			if err := requireRuntimeModelPath(model); err != nil {
				return nil, err
			}
			out[i] = "--model=" + model.Path
			injected = true
		}
	}
	if injected || mode == runtimeModelInjectionOptional {
		return out, nil
	}
	if err := requireRuntimeModelPath(model); err != nil {
		return nil, err
	}
	return append([]string{out[0], "--model", model.Path}, out[1:]...), nil
}

func requireRuntimeModelPath(model modelRuntimeModelView) error {
	if strings.TrimSpace(model.Path) == "" {
		return fmt.Errorf("runtime model path is unavailable")
	}
	if !model.Available {
		return fmt.Errorf("runtime model path is unavailable because --no-extract was set")
	}
	return nil
}

func cloneRuntimeArgs(args []string) []string {
	return append([]string(nil), args...)
}

func modelRunPrimaryModelView(workspace string, manifest modelCapsuleManifestV1, extracted bool) (modelRuntimeModelView, error) {
	artifact, ok := primaryModelRuntimeArtifact(manifest)
	if !ok {
		return modelRuntimeModelView{}, fmt.Errorf("model manifest has no runtime artifact")
	}
	modelRoot := filepath.Join(workspace, "model")
	path, err := signedModelCapsuleMetadataPath(modelRoot, artifact.Path)
	if err != nil {
		path = filepath.Join(modelRoot, artifact.Path)
	}
	return modelRuntimeModelView{
		Path:      path,
		Available: extracted,
	}, nil
}

func primaryModelRuntimeArtifact(manifest modelCapsuleManifestV1) (modelManifestArtifact, bool) {
	for _, artifact := range manifest.Artifacts {
		if strings.EqualFold(strings.TrimSpace(artifact.Kind), modelArtifactKindWeight) {
			return artifact, true
		}
	}
	if len(manifest.Artifacts) > 0 {
		return manifest.Artifacts[0], true
	}
	return modelManifestArtifact{}, false
}
