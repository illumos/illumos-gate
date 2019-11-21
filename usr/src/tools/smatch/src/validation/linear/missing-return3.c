static int foo(int a)
{
	if (a)
		return;
}

static void ref(void)
{
}

/*
 * check-name: missing-return3
 * check-command: sparse -vir -flinearize=last $file
 *
 * check-error-start
linear/missing-return3.c:4:17: error: return with no return value
 * check-error-end
 */
