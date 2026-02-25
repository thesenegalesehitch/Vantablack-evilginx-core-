package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func getNodeVersion() string {
	cmd := exec.Command("node", "--version")
	out, err := cmd.Output()
	if err != nil {
		return "not installed"
	}
	return strings.TrimSpace(string(out))
}

func main() {
	fmt.Println("[*] System Info")
	fmt.Println("OS:", runtime.GOOS)
	fmt.Println("Arch:", runtime.GOARCH)
	fmt.Println("CPU cores:", runtime.NumCPU())
	fmt.Println("Node:", getNodeVersion())
	fmt.Println("Python:", strings.Split(os.Getenv("PYTHON_VERSION"), " ")[0])
}
