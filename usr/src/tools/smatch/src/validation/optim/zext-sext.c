int foo(unsigned char offset)
{
	return (int)(short) offset;
}

/*
 * check-name: zext-sext
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: sext\\.
 * check-output-pattern(1): zext\\.
 */
