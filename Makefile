test: build
	rm -rf ~/.docker/machine/machines/*
	docker-machine -D create --driver timeweb --timeweb-preset-id=3346 test

build:
	go build -o ~/.rd/bin/docker-machine-driver-timeweb
	cp ~/.rd/bin/docker-machine-driver-timeweb ~/go/bin/docker-machine-driver-timeweb
