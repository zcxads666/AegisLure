package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type module struct {
	Path    string  `json:"Path"`
	Version string  `json:"Version"`
	Sum     string  `json:"Sum"`
	Main    bool    `json:"Main"`
	Replace *module `json:"Replace"`
}

type packageEntry struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	Supplier         string `json:"supplier"`
	Comment          string `json:"comment,omitempty"`
}

type document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      creationInfo   `json:"creationInfo"`
	Packages          []packageEntry `json:"packages"`
}

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

func main() {
	output := flag.String("output", "sbom.spdx.json", "SPDX JSON output path")
	root := flag.String("root", ".", "repository root containing go.mod and go.sum")
	flag.Parse()
	if strings.TrimSpace(*output) == "" {
		fatal(errors.New("output path is required"))
	}
	modules, err := listModules(*root)
	if err != nil {
		fatal(err)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	packages := make([]packageEntry, 0, len(modules))
	for _, item := range modules {
		name := item.Path
		version := item.Version
		if item.Replace != nil {
			name += " (replaced by " + item.Replace.Path + ")"
			if item.Replace.Version != "" {
				version += " => " + item.Replace.Version
			}
		}
		entry := packageEntry{
			SPDXID:           "SPDXRef-Package-" + packageID(item.Path),
			Name:             name,
			VersionInfo:      version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  "NOASSERTION",
			Supplier:         "NOASSERTION",
		}
		if item.Sum != "" {
			// Go's module authentication value is an h1/base64 checksum, not a
			// raw SHA-256 digest, so retain it as package provenance rather than
			// mislabeling it as an SPDX SHA256 checksum.
			entry.Comment = "go_module_sum=" + item.Sum
		}
		packages = append(packages, entry)
	}
	document := document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "AegisLure Go module dependency inventory",
		DocumentNamespace: "https://github.com/zcxads666/AegisLure/sbom/standalone-v1",
		CreationInfo:      creationInfo{Created: time.Now().UTC().Format(time.RFC3339), Creators: []string{"Tool: aegislure-sbom"}},
		Packages:          packages,
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*output, append(encoded, '\n'), 0600); err != nil {
		fatal(err)
	}
	fmt.Printf("sbom=%s\npackages=%d\n", *output, len(packages))
}

func listModules(root string) ([]module, error) {
	root = filepath.Clean(root)
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}
	modules := make(map[string]module)
	var modulePath string
	inRequireBlock := false
	for _, rawLine := range strings.Split(string(goMod), "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "//", 2)[0])
		if strings.HasPrefix(line, "module ") {
			modulePath = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			continue
		}
		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}
		if inRequireBlock || strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				modules[parts[0]+"\x00"+parts[1]] = module{Path: parts[0], Version: parts[1]}
			}
		}
	}
	if modulePath == "" {
		return nil, errors.New("go.mod has no module path")
	}
	modules["main\x00"+modulePath] = module{Path: modulePath, Version: "local", Main: true}
	if sums, readErr := os.ReadFile(filepath.Join(root, "go.sum")); readErr == nil {
		for _, line := range strings.Split(string(sums), "\n") {
			parts := strings.Fields(line)
			if len(parts) != 3 {
				continue
			}
			version := strings.TrimSuffix(parts[1], "/go.mod")
			key := parts[0] + "\x00" + version
			item := modules[key]
			if item.Path == "" {
				item = module{Path: parts[0], Version: version}
			}
			if strings.HasPrefix(parts[2], "h1:") && item.Sum == "" {
				item.Sum = parts[2]
			}
			modules[key] = item
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, fmt.Errorf("read go.sum: %w", readErr)
	}
	result := make([]module, 0, len(modules))
	for _, item := range modules {
		result = append(result, item)
	}
	return result, nil
}

func packageID(path string) string {
	digest := sha256.Sum256([]byte(path))
	return hex.EncodeToString(digest[:8])
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "aegislure-sbom:", err)
	os.Exit(1)
}
