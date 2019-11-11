static inline int fun(int a)
{
	if (a)
		return 1;
}

static int foo(int a)
{
	return fun(a);
}

/*
 * check-name: missing-return1
 * check-command: sparse -vir -flinearize=last $file
 */
