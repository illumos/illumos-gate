unsigned int foo(unsigned char x)
{
	return (unsigned int)x & 0xffffU;
}

/*
 * check-name: zext-and
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: and\\.
 */
