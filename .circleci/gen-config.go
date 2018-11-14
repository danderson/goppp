package main

import (
	"html/template"
	"log"
	"os"
)

func main() {
	tmpl := template.Must(template.ParseFiles("config.yml.tmpl"))
	v := map[string][]string{
		"GoVersions": []string{"1.11"},
		"Binary":     []string{"controller", "speaker", "test-bgp-router"},
		"Arch":       []string{"amd64", "arm", "arm64", "ppc64le", "s390x"},
	}
	if err := tmpl.Execute(os.Stdout, v); err != nil {
		log.Fatalf("Error executing template: %s", err)
	}
}
