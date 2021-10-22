package main

import "fmt"

// VersionCmd represents the version command.
type VersionCmd struct{}

// Run the version command to print version information.
func (cmd *VersionCmd) Run() error {
	fmt.Printf("piv-agent %v (%v) compiled with %v on %v\n", version,
		shortCommit, goVersion, date)
	return nil
}
