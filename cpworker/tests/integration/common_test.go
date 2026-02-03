package integration

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Common test utilities

// setupTestOutputDir creates and cleans the output directory for a test
func setupTestOutputDir(t *testing.T, testName string) string {
	outputDir := filepath.Join(getOutputDir(), testName)

	// Remove existing output directory
	if err := os.RemoveAll(outputDir); err != nil && !os.IsNotExist(err) {
		t.Fatalf("Failed to clean output directory: %v", err)
	}

	// Create fresh output directory
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}

	return outputDir
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// getTestDataDir returns the path to the testdata directory
func getTestDataDir() string {
	return "testdata"
}

// getCasesDir returns the path to the test cases directory
func getCasesDir() string {
	return filepath.Join(getTestDataDir(), "cases")
}

// getOutputDir returns the path to the test output directory
func getOutputDir() string {
	return filepath.Join(getTestDataDir(), "output")
}
