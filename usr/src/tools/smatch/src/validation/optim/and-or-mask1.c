int foo(int a, int b)
{
	return ((a & 0x0fffffff) | b) & 0xfff;
}

/*
 * check-name: and-or-mask1
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): and\\.
 * check-output-pattern(1): or\\.
 */
