unsigned int foo(unsigned int x)
{
	return (x << 20) >> 20;
}

/*
 * check-name: shift-zext
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: and\\..*%arg1, \\$0xfff
 */
