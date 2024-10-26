build:
	# go build -o bin/$(shell basename $(PWD)) cmd/main.go
	go build -o bin/n8s *.go