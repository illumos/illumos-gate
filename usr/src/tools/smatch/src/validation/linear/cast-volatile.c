static int foo(volatile int *a, int v)
{
	*a = v;
	return *a;
}

/*
 * check-name: cast-volatile
 * check-command: test-linearize -fdump-ir=linearize $file
 *
 * check-output-ignore
 * check-output-excludes: sext\\.
 * check-output-excludes: zext\\.
 * check-output-excludes: trunc\\.
 */
