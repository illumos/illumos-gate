extern int arr[];
int test_arr_addr(int i)
{
	if (!&arr) return 1;
	return 0;
}

int test_arr_addr0(int i)
{
	if (!&arr[0]) return 1;
	return 0;
}

int test_arr_degen(int i)
{
	if (!arr) return 1;
	return 0;
}

extern int fun(void);
int test_fun_addr(int i)
{
	if (!&fun) return 1;
	return 0;
}

int test_fun_degen(int i)
{
	if (!fun) return 1;
	return 0;
}

/*
 * check-name: degenerate logical-not
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: load
 * check-output-excludes: VOID
 */
