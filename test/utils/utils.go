package test_utils

import (
	"os"
	"path/filepath"
)

func GetJsonFilePaths(path string) ([]string, error) {
	var files []string
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(p) == ".json" {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}
