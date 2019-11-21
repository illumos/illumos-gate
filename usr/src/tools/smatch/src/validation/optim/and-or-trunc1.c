char foo(int x, int y)
{
	return (x & 0xffff) | y;
}

/*
 * check-name: and-or-trunc1
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: and\\.
 */
