package util

import "os"

func ReadFile(file string) ([]byte, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return content, nil
}

func CheckForFile(file string) (bool, error) {
	_, err := os.Stat(file)
	if err != nil {
		return false, err
	} else {
		return true, err
	}
}
