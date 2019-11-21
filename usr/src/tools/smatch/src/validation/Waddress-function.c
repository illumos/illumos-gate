extern void func(void);

int global_function(void)
{
	if (func)
		return 1;
	return 0;
}

/*
 * check-name: Waddress-function
 * check-command: sparse -Wno-decl -Waddress $file
 *
 * check-error-start
Waddress-function.c:5:13: warning: the address of a function will always evaluate as true
 * check-error-end
 */
