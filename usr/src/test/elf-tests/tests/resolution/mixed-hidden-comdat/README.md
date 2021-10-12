This is a test that COMDAT sections with differing visibilities get resolved
to the most restrictive visibility, by the usual rules of symbol
resolution.

The GNU compiler, or build systems which use `-fvisibility*` inconsistently
often emit technically incorrect COMDAT sections where by the sections are not
strictly equivalent because they differ in visibility.  This tests that we
resolve, and resolve them to the most restrictive visibility as the compiler
expects.

We do this...

- `visible.s`
	defines our two COMDAT symbols/sections (`data_symbol` and `bss_symbol`)
	with default visibility

- `hidden.s`
	defines our two COMDAT symbols/sections (`data_symbol` and
	`bss_symbol`) with hidden visibility

- `access.S`
	provides access to our data using relocations we control,
	just in case

- `main.c`
	an actual test wrapper that just checks the values of the
	data

- `Makefile.test`
	A Makefile to build the tests on the system under test

...and check that the resulting `test` binary links and runs.

For an added check we intentionally break the COMDAT rules ourselves, and know
a little bit about the link-editor implementation.  `hidden.s` and `visible.s`
give `data_symbol` _different values_.  We know based on the link-editor
implementation that the first section seen will be the one taken by the
link-editor, so we check for the value from `data.s`, but implicitly rely on the
_visibility_ from `hidden.s` to link.  Proving to ourselves that the visibility
came from symbol resolution and not any other means.
