package client

import (
	"fmt"
	"os"
)

var helpAuth = &Command{
	UsageLine: "auth",
	Short:     "Explains authentication variables",
	Long: `

The authentication variables are how the knox client communicates who is performing an action.

If the $KNOX_USER_AUTH env variable is set, the value will be used as an OAuth token for authenticating the user.

If the $KNOX_MACHINE_AUTH env variable is set, the value will be used as the current client hostname. 

See also: knox login
	`,
}

var usageTemplate = `Knox is a tool for storing and rotating keys.

Usage:

	knox command [arguments]

The commands are:
{{range .}}{{if .Runnable}}
    {{.Name | printf "%-14s"}} {{.Short}}{{end}}{{end}}

Use "knox help [command]" for more information about a command.

Additional help topics:
{{range .}}{{if not .Runnable}}
    {{.Name | printf "%-14s"}} {{.Short}}{{end}}{{end}}

Use "knox help [topic]" for more information about that topic.

`

var helpTemplate = `{{if .Runnable}}usage: knox {{.UsageLine}}

{{end}}{{.Long | trim}}
`

// help implements the 'help' command.
func help(args []string) {
	if len(args) == 0 {
		printUsage(os.Stdout)
		// not exit 2: succeeded at 'go help'.
		return
	}
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: knox help command\n\nToo many arguments given.\n")
		os.Exit(2) // failed at 'go help'
	}

	arg := args[0]

	for _, cmd := range commands {
		if cmd.Name() == arg {
			tmpl(os.Stdout, helpTemplate, cmd)
			// not exit 2: succeeded at 'knox help cmd'.
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Unknown help topic %#q.  Run 'knox help'.\n", arg)
	os.Exit(2) // failed at 'knox help cmd'
}
