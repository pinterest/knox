// This file uses code from http://golang.org/src/cmd/go/main.go
// modified for use with Knox
//
// Copyright (c) 2012 The Go Authors. All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:

//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package client

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"text/template"
	"unicode"
	"unicode/utf8"

	"github.com/pinterest/knox"
)

var cli knox.APIClient

// VisibilityParams exposes functions for the knox client to provide information
type VisibilityParams struct {
	Logf    func(string, ...interface{})
	Errorf  func(string, ...interface{})
	Metrics func(map[string]uint64)
}

var logf = func(string, ...interface{}) {}
var errorf = func(string, ...interface{}) {}
var daemonReportMetrics = func(map[string]uint64) {}
var knoxAuthClientID = ""
var knoxOAuthTokenEndpoint = ""

// Run is how to execute commands. It uses global variables and isn't safe to call in parallel.
func Run(client knox.APIClient, p *VisibilityParams, tokenEndpoint, clientID string) {
	cli = client
	if p != nil {
		if p.Logf != nil {
			logf = p.Logf
		}
		if p.Errorf != nil {
			errorf = p.Errorf
		}
		if p.Metrics != nil {
			daemonReportMetrics = p.Metrics
		}
	}
	knoxAuthClientID = clientID
	knoxOAuthTokenEndpoint = tokenEndpoint

	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		usage()
	}

	if args[0] == "help" {
		help(args[1:])
		return
	}

	for _, cmd := range commands {
		if cmd.Name() == args[0] && cmd.Run != nil {
			cmd.Flag.Usage = func() { cmd.Usage() }
			if cmd.CustomFlags {
				args = args[1:]
			} else {
				cmd.Flag.Parse(args[1:])
				args = cmd.Flag.Args()
			}
			cmd.Run(cmd, args)
			exit()
			return
		}
	}

	fmt.Fprintf(os.Stderr, "knox: unknown subcommand %q\nRun 'knox help' for usage.\n", args[0])
	setExitStatus(2)
	exit()
}

// Commands lists the available commands and help topics.
// The order here is the order in which they are printed by 'knox help'.
var commands = []*Command{
	// These commands are related to running knox as a daemon.
	cmdDaemon,
	cmdRegister,
	cmdUnregister,

	// These commands are related to key management by users.
	cmdGetKeys,
	cmdGet,
	cmdGetVersions,
	cmdGetACL,
	cmdPromote,
	cmdCreate,
	cmdAdd,
	cmdDeactivate,
	cmdReactivate,
	cmdUpdateAccess,
	cmdDelete,
	cmdLogin,

	// These are additional help topics
	helpAuth,
}

// A Command is an implementation of a go command
// like go build or go fix.
type Command struct {
	// Run runs the command.
	// The args are the arguments after the command name.
	Run func(cmd *Command, args []string)

	// UsageLine is the one-line usage message.
	// The first word in the line is taken to be the command name.
	UsageLine string

	// Short is the short description shown in the 'go help' output.
	Short string

	// Long is the long message shown in the 'go help <this-command>' output.
	Long string

	// Flag is a set of flags specific to this command.
	Flag flag.FlagSet

	// CustomFlags indicates that the command will do its own
	// flag parsing.
	CustomFlags bool
}

// Name returns the command's name: the first word in the usage line.
func (c *Command) Name() string {
	name := c.UsageLine
	i := strings.Index(name, " ")
	if i >= 0 {
		name = name[:i]
	}
	return name
}

// Usage prints the help string for a command.
func (c *Command) Usage() {
	fmt.Fprintf(os.Stderr, "usage: %s\n\n", c.UsageLine)
	fmt.Fprintf(os.Stderr, "%s\n", strings.TrimSpace(c.Long))
	os.Exit(2)
}

// Runnable reports whether the command can be run; otherwise
// it is a documentation pseudo-command such as importpath.
func (c *Command) Runnable() bool {
	return c.Run != nil
}

var exitStatus = 0
var exitMu sync.Mutex

func setExitStatus(n int) {
	exitMu.Lock()
	if exitStatus < n {
		exitStatus = n
	}
	exitMu.Unlock()
}

// tmpl executes the given template text on data, writing the result to w.
func tmpl(w io.Writer, text string, data interface{}) {
	t := template.New("top")
	t.Funcs(template.FuncMap{"trim": strings.TrimSpace, "capitalize": capitalize})
	template.Must(t.Parse(text))
	if err := t.Execute(w, data); err != nil {
		panic(err)
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToTitle(r)) + s[n:]
}

func printUsage(w io.Writer) {
	tmpl(w, usageTemplate, commands)
}

func usage() {
	// special case "go test -h"
	if len(os.Args) > 1 && os.Args[1] == "test" {
		help([]string{"testflag"})
		os.Exit(2)
	}
	printUsage(os.Stderr)
	os.Exit(2)
}

func exit() {
	os.Exit(exitStatus)
}

func fatalf(format string, args ...interface{}) {
	errorf(format, args...)
	setExitStatus(1)
	exit()
}
