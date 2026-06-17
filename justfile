dev:
    pip install -e ".[dev]"

test:
    pytest tests/

lint:
    ruff check lns rules tests
    mypy lns

build:
    python -m build
