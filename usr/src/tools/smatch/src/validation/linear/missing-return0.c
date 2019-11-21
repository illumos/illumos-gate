static int foo(int a)
{
	if (a)
		return 1;
}

/*
 * check-name: missing-return0
 * check-command: sparse -vir -flinearize=last $file
 */
