package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cuhawk/BastionAuth/internal/migrationlint"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: migrationlint MIGRATIONS_DIRECTORY")
	}
	paths, err := filepath.Glob(filepath.Join(os.Args[1], "*.sql"))
	if err != nil {
		log.Fatal(err)
	}
	if len(paths) == 0 {
		log.Fatal("no SQL migrations found")
	}
	scripts := make([]string, 0, len(paths))
	for _, path := range paths {
		sql, err := os.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		scripts = append(scripts, string(sql))
	}
	if err := migrationlint.Check(scripts...); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("linted %d migrations\n", len(paths))
}
