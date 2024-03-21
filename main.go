package main

import (
	"embed"

	"github.com/chia-network/repo-content-updater/cmd"
)

//go:embed templates/*
var fs embed.FS

func main() {
	cmd.Execute(fs)
}
