.PHONY: build build-check build-scan clean checksums

build: build-check build-scan

build-check:
	mkdir -p dist
	python3 -m zipapp patch_checker -p '/usr/bin/env python3' -o dist/patch-checker-check.pyz -m patch_checker.cli:main

build-scan:
	mkdir -p dist
	shiv -e patch_checker.cli:main -o dist/patch-checker-scan.pyz . --reproducible

clean:
	rm -rf dist/

checksums:
	cd dist && \
	if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum *.pyz > SHA256SUMS; \
	else \
		shasum -a 256 *.pyz > SHA256SUMS; \
	fi
