short smask(short x)
{
	return x & (short) 0x7fff;
}

short umask(unsigned short x)
{
	return x & (unsigned short) 0x7fff;
}

/*
 * check-name: and-trunc
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: sext\\.
 * check-output-excludes: zext\\.
 * check-output-excludes: trunc\\.
 * check-output-contains: and\\.16
 */
