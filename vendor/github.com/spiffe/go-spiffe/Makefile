ROOT := github.com/spiffe/go-spiffe
PACKAGE_LIST := uri spiffe

test: vet
	@for p in $(PACKAGE_LIST); do \
		go test $(ROOT)/$$p || exit 1; \
	done

vet:
	@for p in $(PACKAGE_LIST); do \
		go vet $(ROOT)/$$p; \
	done
