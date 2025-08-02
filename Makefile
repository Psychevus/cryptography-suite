.PHONY: docs-support-matrix

docs-support-matrix:
	python tools/generate_support_matrix.py
	git diff --exit-code README.md
