module github.com/negashev/docker-machine-driver-timeweb

go 1.23.0

toolchain go1.23.8

require (
	github.com/GIT_USER_ID/GIT_REPO_ID v0.0.0-00010101000000-000000000000
	github.com/docker/machine v0.16.2
)

require github.com/stretchr/testify v1.10.0 // indirect

require (
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/docker/docker v20.10.12+incompatible // indirect
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/term v0.31.0 // indirect
)

replace github.com/GIT_USER_ID/GIT_REPO_ID => github.com/timeweb-cloud/sdk-go v0.0.0-20250407141950-761a0c4661d1
