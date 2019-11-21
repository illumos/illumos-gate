static int foo(int a)
{
	switch (a)
	case 3:
		return 4;
}

/*
 * check-name: missing-return2
 * check-command: sparse -vir -flinearize=last $file
 */
