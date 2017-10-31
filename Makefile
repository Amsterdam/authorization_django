.PHONY: release dist build test coverage clean distclean

PYTHON = python3

release: test
	$(PYTHON) setup.py sdist upload

dist: 
	$(PYTHON) setup.py sdist

build:
	$(PYTHON) setup.py build

test:
	$(PYTHON) setup.py test -a "-p no:cacheprovider --verbose --capture=no ."

coverage:
	$(PYTHON) setup.py test -a "-p no:cacheprovider --verbose --cov=authorization_django --cov-report=term --cov-config .coveragerc --capture=no ."

