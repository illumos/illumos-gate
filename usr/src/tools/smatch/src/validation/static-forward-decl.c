static int f(void);

int f(void)
{
	return 0;
}
/*
 * check-name: static forward declaration
 *
 * check-error-start
static-forward-decl.c:3:5: warning: symbol 'f' was not declared. Should it be static?
 * check-error-end
 */
