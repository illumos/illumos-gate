int foo(int x, int y)
{
	return ((x & 0xffffff0f) | y) & 0xfff;
}

/*
 * check-name: and-or-mask2
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: and\\..*\\$0xf0f
 * check-output-excludes: and\\..*\\$0xffffff0f
 */
