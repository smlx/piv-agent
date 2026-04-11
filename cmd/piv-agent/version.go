package main

import (
	"encoding/json"
	"fmt"
	"runtime"
)

// These variables are set by GoReleaser during the build.
var (
	commit      string
	date        string
	projectName string
	version     string
)

// VersionCmd represents the `version` command.
type VersionCmd struct{}

// Run the Version command.
func (*VersionCmd) Run() error {
	v, err := json.Marshal(
		struct {
			ProjectName string
			Version     string
			Commit      string
			BuildDate   string
			GoVersion   string
		}{
			projectName,
			version,
			commit,
			date,
			runtime.Version(),
		})
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(v))
	return err
}
