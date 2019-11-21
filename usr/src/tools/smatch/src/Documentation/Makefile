# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    = -a
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = sparse
SOURCEDIR     = .
BUILDDIR      = build

targets := help
targets += html
targets += man


# Put it first so that "make" without argument is like "make help".
help:

# route all targets to Sphinx using the new "make mode" option.
$(targets): conf.py Makefile
	@$(SPHINXBUILD) -M  $@  "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)

%.1: %.rst man
	@mv build/man/$@ $@

.PHONY: Makefile	# avoid circular deps with the catch-all rule
