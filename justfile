# instala TODO (sistema + venv + deps editable) y lanza la app
up:
    sudo apt-get update && sudo apt-get install -y nmap libpcap-dev
    test -d .venv || python3 -m venv .venv
    .venv/bin/pip install -e ".[dev]"
    .venv/bin/lns

# lanza la app (asume deps ya instaladas)
run:
    .venv/bin/lns

dev:
    pip install -e ".[dev]"

test:
    pytest tests/

lint:
    ruff check lns rules tests
    mypy lns

build:
    python -m build
