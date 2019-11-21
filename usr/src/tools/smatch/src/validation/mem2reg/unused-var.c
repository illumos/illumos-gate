int foo(int a)
{
	switch (a) {
		int u = 1;

	default:
		return a;
	}
}

/*
 * check-name: unused-var
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	ret.32      %arg1


 * check-output-end
 */
