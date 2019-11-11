int foo(unsigned char offset)
{
	return (int)(unsigned short) offset;
}

/*
 * check-name: zext-zext
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: sext\\.
 * check-output-pattern(1): zext\\.
 */
