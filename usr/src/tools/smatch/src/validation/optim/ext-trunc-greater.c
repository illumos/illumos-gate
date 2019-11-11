short sgt(char x)
{
	return (int) x;
}

short ugt(unsigned char x)
{
	return (int) x;
}

/*
 * check-name: ext-trunc-greater
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: trunc\\.
 */
