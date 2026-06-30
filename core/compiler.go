package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func CompileLoader(source, outputPath string, profile *Profile) error {
	tmpDir, err := os.MkdirTemp("", "hollow-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	srcPath := filepath.Join(tmpDir, "loader.c")
	if err := os.WriteFile(srcPath, []byte(source), 0600); err != nil {
		return fmt.Errorf("writing source: %w", err)
	}

	args := buildGCCArgs(srcPath, outputPath, profile)
	cmd := exec.Command(profile.Compile.GCC, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("compilation failed: %w", err)
	}
	return nil
}

func buildGCCArgs(srcPath, outputPath string, profile *Profile) []string {
	args := []string{srcPath, "-o", outputPath, "-lbcrypt", "-w"}
	if profile.Compile.Strip {
		args = append(args, "-s")
	}
	if profile.Compile.OutputType == "dll" {
		args = append(args, "-shared", "-nostartfiles", "-static-libgcc")
	} else {
		args = append(args, "-static")
	}
	return args
}
