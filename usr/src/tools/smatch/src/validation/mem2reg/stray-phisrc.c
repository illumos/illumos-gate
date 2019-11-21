static int foo(int **g)
{
	int i = 1;
	int *a[2];
	int **p;

	a[1] = &i;
	if (g)
		p = g;
	else
		p = &a[0];
	p += 1;			// will point to a[1] = &i
	if (!g)
		**p = 0;
	return i;
}

/*
 * check-name: stray phisrc
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: phisrc\\.
 */
