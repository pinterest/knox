package spiffe_test

import (
	"fmt"
	"log"
	"os"

	spiffe "github.com/spiffe/go-spiffe"
)

func Example_FGetURINamesFromPEM() {
	log.SetFlags(0)

	f, err := os.Open("./testdata/leaf.cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	uris, err := spiffe.FGetURINamesFromPEM(f)
	if err != nil {
		log.Fatal(err)
	}
	if len(uris) == 0 {
		log.Fatal("did not get any URIs")
	}
	for i, uri := range uris {
		fmt.Printf("#%d:: URI:%q", i, uri)
	}

	// Output:
	//  #0:: URI:"spiffe://dev.acme.com/path/service"
}

func Example_GetURINamesFromPEM() {
	log.SetFlags(0)

	uris, err := spiffe.GetURINamesFromPEM(goodCert)
	if err != nil {
		log.Fatal(err)
	}
	if len(uris) == 0 {
		log.Fatal("did not get any URIs")
	}
	for i, uri := range uris {
		fmt.Printf("#%d:: URI:%q", i, uri)
	}

	// Output:
	//  #0:: URI:"spiffe://dev.acme.com/path/service"
}
