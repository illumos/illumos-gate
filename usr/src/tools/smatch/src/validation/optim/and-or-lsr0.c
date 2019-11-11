int foo(int a, int b)
{
	return ((a & 0x00000fff) | b) >> 12;
}

/*
 * check-name: and-or-lsr0
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-excludes: or\\.
 */
