int loop00(int n)
{
	int i, r = 0;

	for (i = 1; i <= n; ++i)
		r += i;
	return r;
}

/*
 * check-name: loop00
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-excludes: store\\.
 * check-output-excludes: load\\.
 */
