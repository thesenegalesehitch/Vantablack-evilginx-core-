package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"
)

func matrixRain() {
	width := 64
	rows := 10
	frames := 15
	fmt.Print("\033[32m")
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for f := 0; f < frames; f++ {
		for i := 0; i < rows; i++ {
			line := make([]byte, width)
			for j := 0; j < width; j++ {
				if r.Intn(2) == 0 {
					line[j] = '0'
				} else {
					line[j] = '1'
				}
			}
			fmt.Println(string(line))
		}
		time.Sleep(30 * time.Millisecond)
	}
	fmt.Print("\033[0m")
}

func glitch(s string) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	out := []rune(s)
	chars := []rune("!@#$%^&*")
	for i := range out {
		if out[i] != ' ' && r.Float32() < 0.02 {
			out[i] = chars[r.Intn(len(chars))]
		}
	}
	return string(out)
}

func main() {
	if os.Getenv("VANTA_MATRIX_RAIN") == "1" {
		matrixRain()
	}
	fmt.Print("\033[92m")
	art := []string{
		"    ██████  ██       ███████ ██  ██ ",
		"    ██   ██ ██       ██      ██  ██ ",
		"    ██████  ██       █████   ██████ ",
		"    ██   ██ ██       ██          ██ ",
		"    ██   ██ ███████  ███████     ██ ",
		"                 A L E X            ",
	}
	for _, line := range art {
		fmt.Println(glitch(line))
		time.Sleep(3 * time.Millisecond)
	}
	fmt.Print("\033[0m")
}
