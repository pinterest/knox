package client

import "fmt"

const defaultVersionString = "devel"

var Version string

var cmdVersion = &Command{
	Run:       runVersion,
	UsageLine: "version",
	Short:     "Prints the current version of the Knox client",
	Long: `
Prints the current version of the Knox client.
`,
}

func runVersion(cmd *Command, args []string) {
	if Version == "" {
		Version = defaultVersionString
	}
	fmt.Printf("Knox CLI version %s\n", Version)
}
