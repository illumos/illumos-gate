int foo(int c, int a, int b)
{
	int l;

	if (c)
		l = a;
	else
		l = b;

	return l;
}

/*
 * check-name: if-then-else direct
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-excludes: load\\.
 * check-output-contains: phi\\.
 */
