char foo(int x, int y, int b)
{
	return (x & y) | (b & 0xff00);
}

/*
 * check-name: and-or-truncx
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): and\\.
 * check-output-excludes: or\\.
 */
