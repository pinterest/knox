package client

import "fmt"

const versionString = "1.2.3"

var cmdVersion = &Command{
	Run:       runVersion,
	UsageLine: "version",
	Short:     "Prints the current version of the Knox client",
	Long: `
Prints the current version of the Knox client.
`,
}

func runVersion(cmd *Command, args []string) {
	fmt.Printf("Knox CLI version %s\n", versionString)
}
