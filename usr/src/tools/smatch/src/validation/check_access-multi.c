extern int *a;
extern int b[1];

static void foo(void)
{
	*a = b[1];
}

/*
 * check-name: check_access-multi
 *
 * check-error-start
check_access-multi.c:6:15: warning: invalid access past the end of 'b' (4 4)
 * check-error-end
 */
