package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	ok := false
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8000/health")
	if err == nil && resp.StatusCode == 200 {
		ok = true
	}
	if ok {
		fmt.Println("API: OK")
	} else {
		fmt.Println("API: DOWN")
	}
}
