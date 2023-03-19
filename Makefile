GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test

GOOS ?= linux
GOARCH ?= amd64

BINARY_NAME=crowdsec-blocklist-mirror

TARBALL_NAME=$(BINARY_NAME).tgz

# Current versioning information from env
BUILD_VERSION?="$(shell git describe --tags)"
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
BUILD_TAG="$(shell git rev-parse HEAD)"

LD_OPTS_VARS=\
-X 'github.com/crowdsecurity/cs-blocklist-mirror/version.Version=$(BUILD_VERSION)' \
-X 'github.com/crowdsecurity/cs-blocklist-mirror/version.BuildDate=$(BUILD_TIMESTAMP)' \
-X 'github.com/crowdsecurity/cs-blocklist-mirror/version.Tag=$(BUILD_TAG)'

ifdef BUILD_STATIC
	export LD_OPTS=-ldflags "-a -v -s -w -extldflags '-static' $(LD_OPTS_VARS)" -tags netgo
else
	export LD_OPTS=-ldflags "-a -v -s -w $(LD_OPTS_VARS)"
endif

.PHONY: all
all: build

# Called during release, to reuse the directory for other platforms
.PHONY: clean-release-dir
clean-release-dir:
	@rm -rf $(RELDIR)

# Remove everything including all platform binaries and tarballs
.PHONY: clean
clean: clean-release-dir
	@rm -f $(BINARY_NAME)
	@rm -f $(TARBALL_NAME)
	@rm -rf $(BINARY_NAME)-*	# platform binary name and leftover release dir
	@rm -f $(BINARY_NAME)-*.tgz	# platform release file

#
# Build binaries
#

.PHONY: binary
binary: goversion
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME)

.PHONY: build
build: goversion clean binary

#
# Unit and integration tests
#

.PHONY: test
test:
	@$(GOTEST) ./...

.PHONY: func-tests
func-tests: build
	pipenv install --dev
	pipenv run pytest -v

#
# Build release tarballs
#

RELDIR = "$(BINARY_NAME)-$(BUILD_VERSION)"

.PHONY: tarball
tarball: binary
	@if [ -z $(BUILD_VERSION) ]; then BUILD_VERSION="local" ; fi
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, please run 'make clean' and retry" ;  exit 1 ; fi
	@echo Building Release to dir $(RELDIR)
	@mkdir $(RELDIR)/
	@cp $(BINARY_NAME) $(RELDIR)/
	@cp -R ./config $(RELDIR)/
	@cp ./scripts/install.sh $(RELDIR)/
	@cp ./scripts/uninstall.sh $(RELDIR)/
	@cp ./scripts/upgrade.sh $(RELDIR)/
	@chmod +x $(RELDIR)/install.sh
	@chmod +x $(RELDIR)/uninstall.sh
	@chmod +x $(RELDIR)/upgrade.sh
	@tar cvzf $(TARBALL_NAME) $(RELDIR)


.PHONY: release
release: clean tarball

#
# Build binaries and release tarballs for all platforms
#

.PHONY: platform-all
platform-all: goversion clean
	python3 .github/release.py run-build $(BINARY_NAME)

# Check if go is the right version
include mk/goversion.mk
