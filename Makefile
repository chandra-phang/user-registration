

.PHONY: clean all init generate generate_mocks

all: build/main

init: generate
	go mod tidy
	go mod vendor
	cert

build/main: cmd/main.go generated
	@echo "Building..."
	go build -o $@ $<

test:
	go test -short -coverprofile coverage.out -v ./...

cert:
	@echo "Generating certificate..."
	openssl genpkey -algorithm RSA -out private-key.pem
	openssl rsa -pubout -in private-key.pem -out public-key.pem

clean:
	rm -rf generated

generate: generated generate_mocks

generated: api.yml
	@echo "Generating files..."
	mkdir generated || true
	oapi-codegen --package generated -generate types,server,spec $< > generated/api.gen.go

INTERFACES_GO_FILES := $(shell find repository -name "interfaces.go")
INTERFACES_GEN_GO_FILES := $(INTERFACES_GO_FILES:%.go=%.mock.gen.go)

generate_mocks: $(INTERFACES_GEN_GO_FILES)
$(INTERFACES_GEN_GO_FILES): %.mock.gen.go: %.go
	@echo "Generating mocks $@ for $<"
	mockgen -source=$< -destination=$@ -package=$(shell basename $(dir $<))
