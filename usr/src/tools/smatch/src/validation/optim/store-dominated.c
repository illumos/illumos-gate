static int a[];

static void foo(void)
{
	int *c = &a[1];
	*c = *c = 0;
}

/*
 * check-name: store-dominated
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: add\\.
 */
