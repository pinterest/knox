# go-spiffe library [![GoDoc](https://godoc.org/github.com/spiffe/go-spiffe?status.svg)](https://godoc.org/github.com/spiffe/go-spiffe)

## Overview

The go-spiffe library provides functionality to parse and verify SPIFFE
identities encoded in X.509 certificates as described in the
[SPIFFE Standards](https://github.com/spiffe/spiffe/tree/master/standards).

## Installing it
```shell
go get -u -v github.com/spiffe/go-spiffe
```

## Importing it in your Go code

See examples in [examples_test.go](./example_test.go)
or visit the [GoDoc](https://godoc.org/github.com/spiffe/go-spiffe) for more information

## Installing the command line interface
The command line interface can be used to retrieve and view URIs stored
in the SAN extension of certificates

```shell
go get -u -v github.com/spiffe/go-spiffe/cmd/spiffe
spiffe testdata/leaf.cert.pem $HOME/certs/proj.pem
Path:: #1: "testdata/leaf.cert.pem"
  URI #1: "spiffe://dev.acme.com/path/service"
```
