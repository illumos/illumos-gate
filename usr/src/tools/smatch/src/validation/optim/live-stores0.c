void init(int *x);

static int foo(void)
{
	int a[2] = { 0, 123, };

	if (a[1] != 123)
		return 1;
	init(a);
	if (a[1] == 123)
		return 2;
	return 0;
}

#if 0
void init(int *x)
{
	x[0] = x[1] = 0;
}
#endif

/*
 * check-name: live-stores
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-contains: store.32 *\\$123
 * check-output-pattern(2,3): store\\.
 */
