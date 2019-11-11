char foo(int x, int y)
{
	return (x & 0xff00) | y;
}

/*
 * check-name: and-or-trunc0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: and\\.
 * check-output-excludes: or\\.
 */
