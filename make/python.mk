.PHONY: lint test test-ci

lint: ## Run black, isort, and mypy
	poetry run ruff format --check src/
	poetry run ruff check src/
	poetry run mypy --check src/

test: ## Run Python tests
	poetry run pytest --cov=src/ --cov-report=term-missing

test-ci: ## Run Python tests with XML coverage report
	poetry run pytest --cov=src/ --cov-report=xml
