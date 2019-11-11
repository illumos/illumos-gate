int foo (int a)
{
	return ((a == 0) & 1) == (a == 0);
}

/*
 * check-name: setcc-mask
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	ret.32      $1


 * check-output-end
 */
