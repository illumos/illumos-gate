extern int g;


static int foo(int *p)
{
	*p = 1;
	g = 2;
	return *p == 1;
}

static int bar(int *p)
{
	g = 1;
	*p = 2;
	return g == 1;
}

static void test(void)
{
	foo(&g);
	bar(&g);
}

/*
 * check-name: alias symbol/pointer
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-excludes: ret\\..* *\\$1
 */
