.PHONY: test test-cov dev run tdx

# Run the full test suite
test:
	python -m pytest tests/ -v

# Run tests with coverage report
test-cov:
	python -m pytest tests/ -v --cov=engine --cov=config --cov-report=term-missing

# Start the API server in development mode (hot reload)
dev:
	ENV=development python main.py

# Start the API server in production mode
run:
	uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4

# Run the TDX polling loop (processes live tickets)
tdx:
	python api/tdx.py
