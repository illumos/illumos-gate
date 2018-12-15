int foo(int a, int b)
{
	int r = a + b;

	if (a && 0) {
		int s = r;
		if (b)
			s = 0;
		(void) s;
	}

	return 0;
}

/*
 * check-name: kill-phisrc
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: add\\.
 */
