int foo(int p, int q, int a)
{
	if (p)
		a = 0;
	if (q)
		a = 1;

	return a;
}

/*
 * check-name: cond-expr5
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 *
 * check-output-ignore
 * check-output-excludes: load\\.
 * check-output-excludes: store\\.
 * check-output-excludes: phi\\..*, .*, .*
 * check-output-pattern(3): phi\\.
 * check-output-pattern(5): phisrc\\.
 */
