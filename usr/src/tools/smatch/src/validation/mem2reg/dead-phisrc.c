static void foo(void)
{
	extern int *a;

	if (a || *a)
		;
	if (a[0] || a[1])
		;
}

/*
 * check-name: dead-phisrc
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: phisrc
 */
