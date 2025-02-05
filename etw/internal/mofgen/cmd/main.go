// File: etw/internal/mofgen/cmd/main.go

/*
The mofgen tool generates Go code for Windows ETW MOF (Managed Object Format) class definitions.

It reads a Windows Kernel Trace MOF file containing ETW event class definitions and generates
corresponding Go structures and helper functions for parsing ETW events.

Usage:
    go run main.go || go generate

The tool will:
1. Find the project root by looking for go.mod
2. Read the MOF file from etw/internal/mofgen/cmd/WindowsKernelTrace.mof
3. Parse the MOF definitions
4. Generate Go code in etw/gen_mof_kerneldef.go

The generated code includes:
- MOF class definitions as Go structs
- Mapping of provider GUIDs to class names
- Helper functions for working with ETW events
- Base event ID calculations for each provider

Generated code is used by the etw package to decode Windows ETW events into Go structures.
*/
package main

//go:generate go run generate.go

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
	mofPath := filepath.Join(projectRoot, "etw", "internal", "mofgen", "cmd", "WindowsKernelTrace.mof")
	outPath := filepath.Join(projectRoot, "etw", "gen_mof_kerneldef.go")

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

	//log.Printf("Successfully generated %s", outPath)
}
