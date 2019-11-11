extern int a[1];

static int r(void)
{
	return a[1];
}

static void w(void)
{
	a[1] = 2;
}

/*
 * check-name: check_access-store
 * check-known-to-fail
 *
 * check-error-start
check_access-store.c:5:17: warning: invalid access past the end of 'a' (4 4)
check_access-store.c:10:17: warning: invalid access past the end of 'a' (4 4)
 * check-error-end
 */
