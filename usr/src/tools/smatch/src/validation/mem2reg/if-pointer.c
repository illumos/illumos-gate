int foo(int c, int a, int b)
{
	int l, *p = &l;

	if (c)
		*p = a;
	else
		*p = b;

	return l + *p;
}

/*
 * check-name: if-then-else pointer
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-known-to-fail
 * check-output-ignore
 * check-output-excludes: load\\.
 * check-output-excludes: store\\.
 * check-output-contains: phi\\.
 */
