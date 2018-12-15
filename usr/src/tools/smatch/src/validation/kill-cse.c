int foo(int a)
{
	return ((a == 0) + 1) != ((a == 0) + 1);
}

/*
 * check-name: kill-cse
 * check-description:
 *	Verify that instructions removed at CSE are
 *	properly adjust the usage of their operands.
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	ret.32      $0


 * check-output-end
 */
