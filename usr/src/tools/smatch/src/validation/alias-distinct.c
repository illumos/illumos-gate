extern int g;
extern int h;

static int foo(void)
{
	g = 1;
	h = 2;
	return g == 1;
}

/*
 * check-name: alias distinct symbols
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..* *\\$1
 */
