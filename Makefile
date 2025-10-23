.PHONY: install test clean

install:
	python -m venv .venv
	. .venv/bin/activate && pip install -r requirements.txt

test:
	. .venv/bin/activate && pytest -q

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} +
	rm -rf .venv build dist *.egg-info