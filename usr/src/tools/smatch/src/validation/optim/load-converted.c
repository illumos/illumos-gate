static int foo(int *p, int i)
{
	int a = p[i];
	int b = p[i];
	return (a - b);
}

/*
 * check-name: load-converted
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: add\\.
 */
