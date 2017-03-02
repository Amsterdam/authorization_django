.PHONY: release dist build test coverage clean distclean

PYTHON = python3
RM = rm -rf

release: clean test
	$(PYTHON) setup.py sdist upload

dist: clean
	$(PYTHON) setup.py sdist

build:
	$(PYTHON) setup.py build

test: clean
	$(PYTHON) setup.py test -a "-p no:cacheprovider --verbose ."

coverage: clean
	$(PYTHON) setup.py test -a "-p no:cacheprovider --verbose --cov=authorization_django --cov-report=term --cov-config .coveragerc ."

clean:
	@$(RM) build/ *.egg-info/ .eggs/ dist/
	@find . \( \
		-iname "*.pyc" \
		-or -iname "*.pyo" \
		-or -iname "*.so" \
		-or -iname "*.o" \
		-or -iname "*~" \
		-or -iname "._*" \
		-or -iname "*.swp" \
		-or -iname "Desktop.ini" \
		-or -iname "Thumbs.db" \
		-or -iname "__MACOSX__" \
		-or -iname ".DS_Store" \
		\) -delete

distclean: clean
	@$(RM) \
		dist/ \
		bin/ \
		develop-eggs/ \
		eggs/ \
		parts/ \
		MANIFEST \
		htmlcov/ \
		.coverage \
		.installed.cfg
