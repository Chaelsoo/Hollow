package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kanyo/hollow/cmd"
)

func main() {
	shellcodePath := flag.String("shellcode", "", "path to raw shellcode .bin file")
	profilePath := flag.String("profile", "", "path to profile .json file")
	templateDir := flag.String("templates", "./templates", "path to templates directory")
	flag.Parse()

	if *shellcodePath == "" || *profilePath == "" {
		fmt.Fprintf(os.Stderr, "usage: mold -shellcode <file.bin> -profile <profile.json>\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	err := cmd.Generate(cmd.GenerateOptions{
		ShellcodePath: *shellcodePath,
		ProfilePath:   *profilePath,
		TemplateDir:   *templateDir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}
}
