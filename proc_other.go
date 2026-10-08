//go:build !windows

package main

import (
	"os/exec"
)

// killProcessByName non-Windows : pkill
func killProcessByName(name string) (string, error) {
	out, err := exec.Command("pkill", "-f", name).CombinedOutput()
	return string(out), err
}

// runHidden non-Windows : exécution directe
func runHidden(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}
