static void foo(void)
{
	int *b;
	for (;;)
		*b++ = 0;
}

/*
 * check-name: undef01
 * check-command: sparse -Wmaybe-uninitialized $file
 * check-known-to-fail
 *
 * check-error-start
crazy04.c:3:13: warning: variable 'b' may be uninitialized
 * check-error-end
 */
