.PHONY: all environment install install-mac install-linux install-windows auto-lint validate test test-example coverage coverage-html coverage-xml coverage-erase generate-sample-data

CODE_COVERAGE ?= 90
WINDOWS_32BIT_GMPY2 ?= packages/gmpy2-2.0.8-cp38-cp38-win32.whl
WINDOWS_64BIT_GMPY2 ?= packages/gmpy2-2.0.8-cp38-cp38-win_amd64.whl
OS ?= $(shell python -c 'import platform; print(platform.system())')
IS_64_BIT ?= $(shell python -c 'from sys import maxsize; print(maxsize > 2**32)')

all: install environment validate auto-lint coverage

environment:
	@echo 🔧 PIPENV SETUP
	pip3 install pipenv
	pipenv install --dev
	pipenv run python -m pip install -e .

install:
	@echo 📦 Install OS-specific
	pip3 install pipenv
	@echo Operating System identified as $(OS)
ifeq ($(OS), Linux)
	make install-linux
endif
ifeq ($(OS), Darwin)
	make install-mac
endif
ifeq ($(OS), Windows)
	make install-windows
endif
ifeq ($(OS), Windows_NT)
	make install-windows
endif

install-mac:
	@echo 🍎 MACOS INSTALL
# gmpy2 requirements
	brew install gmp || true
	brew install mpfr || true
	brew install libmpc || true

install-linux:
	@echo 🐧 LINUX INSTALL
# gmpy2 requirements
	sudo apt-get install libgmp-dev
	sudo apt-get install libmpfr-dev
	sudo apt-get install libmpc-dev

install-windows:
	@echo WINDOWS INSTALL
# install module with local gmpy2 package
ifeq ($(IS_64_BIT), True)
	pipenv run python -m pip install -f $(WINDOWS_64BIT_GMPY2) -e . 
endif
ifeq ($(IS_64_BIT), False)
	pipenv run python -m pip install -f $(WINDOWS_32BIT_GMPY2) -e . 
endif

auto-lint:
	@echo 💚 AUTO LINT
	@echo Reformatting using Black
	pipenv run black .
	make lint
	
lint:
	@echo 💚 LINT
	@echo 1.Pylint
	pipenv run pylint ./src/**/*.py ./tests/**/*.py
	@echo 2.Black Formatting
	pipenv run black --check .
	@echo 3.Mypy Static Typing
	pipenv run mypy src stubs tests setup.py

validate: 
	@echo ✅ VALIDATE
	@pipenv run python -c 'import electionguard; print(electionguard.__package__ + " successfully imported")'

test:
	@echo ✅ ALL TESTS
	@date -u
	pipenv run pytest tests

# Coverage
coverage:
	@echo ✅ COVERAGE
	pipenv run coverage run -m pytest
	pipenv run coverage report --fail-under=$(CODE_COVERAGE)

coverage-html:
	pipenv run coverage html -d coverage

coverage-xml:
	pipenv run coverage xml

coverage-erase:
	@pipenv run coverage erase

autograder:
	pipenv run python autograder.py
