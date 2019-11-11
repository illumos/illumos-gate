int foo(int x)
{
	return (x | 0xfffffff0) & 0xfff;
}

/*
 * check-name: and-or-constant2
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: or\\..*\\$0xff0
 * check-output-excludes: or\\..*\\$0xfffffff0
 */
