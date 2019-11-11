extern int g;


static int foo(void)
{
	g = 1;
	g = 2;
	return g != 1;
}

/*
 * check-name: alias same symbols
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..* *\\$1
 */
