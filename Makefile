.PHONY: release dist build test coverage clean distclean

PYTHON = python3

release: test
	uv build
	uv publish

dist:
	uv build

build:
	uv build

test:
	uv run pytest -p no:cacheprovider --verbose --capture=no .

coverage:
	uv run pytest -p no:cacheprovider --verbose --cov-report=term-missing --capture=no .
