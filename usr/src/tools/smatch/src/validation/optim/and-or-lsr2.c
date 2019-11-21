int foo(int x, int y)
{
	return ((x & 0xf0ffffff) | y) >> 12;
}

/*
 * check-name: and-or-lsr2
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: and\\..*\\$0xf0fff
 * check-output-excludes: and\\..*\\$0xf0ffffff
 */
