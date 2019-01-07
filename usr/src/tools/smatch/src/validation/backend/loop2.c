extern int op(void);

static void test(void)
{
	int i;
	for (i = 0; ; i++) {
		op();
	}
}

/*
 * check-name: Loops with unused counter
 * check-command: sparsec -c $file -o tmp.o
 */
