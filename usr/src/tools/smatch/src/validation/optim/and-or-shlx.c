unsigned int foo(unsigned int x, unsigned int y, unsigned int a)
{
	return ((x & y) | (a & 0xfff00000)) << 12;
}

/*
 * check-name: and-or-shlx
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): and\\.
 * check-output-excludes: or\\.
 */
