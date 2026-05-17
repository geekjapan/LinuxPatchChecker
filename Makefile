.PHONY: build build-check build-scan clean checksums

build: build-check build-scan

build-check:
	bash scripts/build_check.sh

build-scan:
	bash scripts/build_scan.sh

clean:
	rm -rf dist/

checksums: build
	cd dist && \
	if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum *.pyz > SHA256SUMS; \
	else \
		shasum -a 256 *.pyz > SHA256SUMS; \
	fi
