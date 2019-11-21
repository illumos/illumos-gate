static void foo(void)
{
	unsigned short p = 0;
	int x;

	for (;;)
		if (p)
			p = x;
}

/*
 * check-name: cse-size
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(2): phi\\.
 */
