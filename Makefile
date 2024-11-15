.PHONY: clean critic security lint

APP_NAME = api-auth
BUILD_DIR = $(PWD)/build

clean:
	rm -rf ./build

critic:
	gocritic check -enableAll ./...

lint:
	golangci-lint run ./...
