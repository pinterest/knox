package client

import (
	"fmt"
)

var cmdListKeyTemplates = &Command{
	Run:       runListKeyTemplates,
	UsageLine: "key-templates",
	Short:     "Lists the supported tink key templates",
	Long: `
	Lists the supported tink key templates.
`,
}

func runListKeyTemplates(cmd *Command, args []string) {
	fmt.Println("The following tink key templates are supported:")
	fmt.Println(nameOfSupportedTinkKeyTemplates())
}
