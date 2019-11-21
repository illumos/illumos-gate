int foo(int a, int b)
{
	return ((a & 0x000fffff) | b) << 12;
}

/*
 * check-name: and-or-shl1
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(0): and\\.
 * check-output-pattern(1): or\\.
 */
