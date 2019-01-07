void foo(void)
{
	int a = 1;
	while ((a = !a))
		;
}

/*
 * check-name: infinite loop 02
 * check-command: sparse -Wno-decl $file
 */
