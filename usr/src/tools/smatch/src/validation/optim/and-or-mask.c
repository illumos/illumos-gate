int foo(int a, int b)
{
	return ((a & 7) | (b & 3)) & 8;
}

/*
 * check-name: and-or-mask
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	ret.32      $0


 * check-output-end
 */
