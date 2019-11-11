int foo(int a, int b)
{
	return ((a & 0xfff00000) | b) << 12;
}

/*
 * check-name: and-or-shl0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: or\\.
 */
