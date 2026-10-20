BINARY := tpm-fido

.PHONY: all build test package clean help

all: build

build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o $(BINARY) .

test:
	go test -race ./...

package:
	./packaging/build-deb.sh

clean:
	rm -f $(BINARY)
	rm -rf build/deb

help:
	@printf '%s\n' \
		'make build    Build the daemon' \
		'make test     Run the race-enabled unit test suite' \
		'make package  Build the Ubuntu 26.04 Debian package with Docker' \
		'make clean    Remove local build artifacts'
