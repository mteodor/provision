
BUILD_DIR = build
SERVICES = provision
CGO_ENABLED ?= 0
GOARCH ?= amd64

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) go build -mod=vendor -ldflags "-s -w" -o ${BUILD_DIR}/mainflux-$(1) cmd/main.go
endef

all: $(SERVICES)

.PHONY: all $(SERVICES) docker

$(SERVICES):
	$(call compile_service,$(@))

docker:
	docker build \
		--no-cache \
		--build-arg SVC=provision \
		--build-arg GOARCH=$(GOARCH) \
		--build-arg GOARM=$(GOARM) \
		--tag=mainflux/provision-service \
		-f docker/Dockerfile .
