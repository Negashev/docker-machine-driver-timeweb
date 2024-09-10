test: build
	rm -rf ~/.docker/machine/machines/*
	docker-machine -D create --driver timeweb test

build:
	go build -o ~/.rd/bin/docker-machine-driver-timeweb
