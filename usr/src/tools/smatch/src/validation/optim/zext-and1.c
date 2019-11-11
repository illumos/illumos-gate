unsigned int bar(unsigned char x)
{
	return (unsigned int)x & 0xff01U;
}

/*
 * check-name: zext-and1
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: and\\..*\\$1
 */
