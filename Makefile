export GOPATH  = $(shell pwd)/.gopath
export GOCACHE = $(shell pwd)/.gocache
export GOBIN   = $(shell pwd)/bin

GO=CGO_ENABLED=0 go
VPATH=main
NAME=check-log4shell

export THE_GIT_BRANCH ?= $(shell git branch | grep '^*' | awk '{print $$2}')
export THE_GIT_COMMIT ?= $(shell git rev-parse HEAD)
export THE_GIT_DIRTY ?= $(shell test -n "`git status --porcelain`" && echo "+CHANGES" || true)
export BUILD_TIME ?= $(shell date +%s)
export VERSION ?= 0000

LDFLAGS += -X $(VPATH).BuildTime=$(BUILD_TIME)
LDFLAGS += -X $(VPATH).GitBranch=$(THE_GIT_BRANCH)
LDFLAGS += -X $(VPATH).GitCommit=$(THE_GIT_COMMIT)$(THE_GIT_DIRTY)
LDFLAGS += -X $(VPATH).Build=$(VERSION)
LDFLAGS += -X $(VPATH).Version=$(VERSION)
LDFLAGS += -X $(VPATH).Name=$(NAME)

.PHONY: build
build:
	$(GO) build -o $(GOBIN)/$(NAME) -mod=vendor --ldflags "$(LDFLAGS)" --gcflags=all=--trimpath=$(shell pwd)

.PHONY: build-win
build-win:
	GOOS=windows GOARCH=amd64 $(GO) build -o $(GOBIN)/$(NAME).exe -mod=vendor --ldflags "$(LDFLAGS)" --gcflags=all=--trimpath=$(shell pwd)

.PHONY: mod-tidy
mod-tidy:
	@$(GO) mod tidy
	@$(GO) mod vendor

.PHONY: clean
clean:
	@$(GO) clean -cache
	@$(GO) clean -modcache

