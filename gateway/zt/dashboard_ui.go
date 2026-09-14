package main

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

var (
	//go:embed dashboard-ui/dist
	dashboardUIEmbeddedFS embed.FS
	dashboardUIFS         = mustDashboardUIFS()
)

func mustDashboardUIFS() fs.FS {
	sub, err := fs.Sub(dashboardUIEmbeddedFS, "dashboard-ui/dist")
	if err != nil {
		panic("dashboard ui dist missing: " + err.Error())
	}
	return sub
}

func serveDashboardUI(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if cleaned == "" || cleaned == "." {
		cleaned = "index.html"
	}
	if serveDashboardUIAsset(w, r, cleaned) {
		return
	}
	// SPA fallback: paths without extension return index.html.
	if !strings.Contains(path.Base(cleaned), ".") && serveDashboardUIAsset(w, r, "index.html") {
		return
	}
	http.NotFound(w, r)
}

func serveDashboardUIAsset(w http.ResponseWriter, r *http.Request, name string) bool {
	raw, err := fs.ReadFile(dashboardUIFS, name)
	if err != nil {
		return false
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-store")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=300")
	}
	if ctype := mime.TypeByExtension(path.Ext(name)); strings.TrimSpace(ctype) != "" {
		w.Header().Set("Content-Type", ctype)
	}
	if r != nil && r.Method == http.MethodHead {
		return true
	}
	_, _ = w.Write(raw)
	return true
}
