package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/tekert/golang-etw/etw/internal/mofgen"
)

// findProjectRoot returns the absolute path to the project root directory
// by walking up from the current source file until finding go.mod
func findProjectRoot() (string, error) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to get current file path")
	}

	dir := filepath.Dir(currentFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found in parent directories")
		}
		dir = parent
	}
}

func main() {

    projectRoot, err := findProjectRoot()
    if err != nil {
        log.Fatalf("Failed to find project root: %v", err)
    }
	mofPath := filepath.Join(projectRoot, "etw", "cmd", "mofgen", "WindowsKernelTrace.mof")
    outPath := filepath.Join(projectRoot, "etw", "beta_etw_mof_defs_generated3.go")

	// // Get directory containing main.go
	// projectRoot, err := os.Getwd()
	// if err != nil {
	// 	log.Fatalf("Failed to get working directory: %v", err)
	// }
	// mofPath := filepath.Clean(filepath.Join(projectRoot, "etw", "cmd", "mofgen", "WindowsKernelTrace.mof"))
	// outPath := filepath.Clean(filepath.Join(projectRoot, "etw", "beta_etw_mof_defs_generated2.go"))

	// Read MOF content
	mofContent, err := os.ReadFile(mofPath)
	if err != nil {
		log.Fatalf("Failed to read MOF file: %v", err)
	}

	// Parse MOF and generate Go code
	goCode, err := mofgen.Parse(string(mofContent))
	if err != nil {
		log.Fatalf("Failed to parse MOF: %v", err)
	}

	// Write generated code to file
	err = os.WriteFile(outPath, []byte(goCode), 0644)
	if err != nil {
		log.Fatalf("Failed to write output file: %v", err)
	}

	log.Printf("Successfully generated %s", outPath)
}
