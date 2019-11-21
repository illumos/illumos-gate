static long p2l(long *p)
{
	return (long) p;
}

static long *l2p(long l)
{
	return (long*)l;
}

/*
 * check-name: cast-nop
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: utptr\\.
 * check-output-excludes: ptrtu\\.
 */
