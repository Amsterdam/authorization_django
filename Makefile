.PHONY: release dist build test coverage clean distclean

PYTHON = python3

release: test
	$(PYTHON) setup.py sdist upload

dist: 
	$(PYTHON) setup.py sdist

build:
	$(PYTHON) setup.py build

test:
	pytest -p no:cacheprovider --verbose --capture=no .

coverage:
	pytest -p no:cacheprovider --verbose --cov=authorization_django --cov-report=term --cov-config .coveragerc --capture=no .

