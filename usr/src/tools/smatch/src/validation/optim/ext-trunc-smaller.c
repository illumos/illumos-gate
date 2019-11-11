char  slt(short x)
{
	return (int) x;
}

char  ult(unsigned short x)
{
	return (int) x;
}

/*
 * check-name: ext-trunc-smaller
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: sext\\.
 * check-output-excludes: zext\\.
 */
