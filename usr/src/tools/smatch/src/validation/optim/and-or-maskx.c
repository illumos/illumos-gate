int foo(int x, int y, int a)
{
	return ((x & y) | (a & 0xf000)) & 0x0fff;
}

/*
 * check-name: and-or-maskx
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(2): and\\.
 * check-output-excludes: or\\.
 */
