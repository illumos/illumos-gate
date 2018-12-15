extern void func(void);

int global_function(void)
{
	if (func)
		return 1;
	return 0;
}

/*
 * check-name: cond-address-function
 * check-command: test-linearize -Wno-decl -Waddress $file
 * check-output-ignore
 *
 * check-error-start
cond-address-function.c:5:13: warning: the address of a function will always evaluate as true
 * check-error-end
 */
