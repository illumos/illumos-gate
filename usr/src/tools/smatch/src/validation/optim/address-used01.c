int foo(int **g, int j)
{
	int i = 1;
	int *a;
	int **p;

	a = &i;
	p = &a;
	*p[0] = 0;
	return i;
}

/*
 * check-name: address-used01
 * check-command: test-linearize -Wno-decl -fdump-ir=final $file
 * check-output-ignore
 * check-output-contains: ret\\..* \\$0
 */
