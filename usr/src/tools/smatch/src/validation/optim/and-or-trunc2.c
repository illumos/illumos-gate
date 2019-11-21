char foo(int x, int y)
{
	return (x & 0xff07) | y;
}

/*
 * check-name: and-or-trunc2
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): and\\.
 * check-output-pattern(1): and\\..*\\$7
 */
