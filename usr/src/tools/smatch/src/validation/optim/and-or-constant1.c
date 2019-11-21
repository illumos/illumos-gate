int foo(int x)
{
	return (x | 0x000fffff) & 0xfff;
}

/*
 * check-name: or-and-constant1
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$0xfff
 * check-output-excludes: and\\.
 * check-output-excludes: or\\.
 */
