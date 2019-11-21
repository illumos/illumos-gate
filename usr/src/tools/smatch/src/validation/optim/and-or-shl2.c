int foo(int x, int y)
{
	return ((x & 0xffffff0f) | y) << 12;
}

/*
 * check-name: and-or-shl2
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: and\\..*\\$0xfff0f
 * check-output-excludes: and\\..*\\$0xffffff0f
 */
