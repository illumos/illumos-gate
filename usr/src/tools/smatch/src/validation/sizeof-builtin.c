int test(void);
int test(void)
{
	return sizeof &__builtin_trap;
}

/*
 * check-name: sizeof-builtin
 * check-command: sparse -Wno-decl $file
 * check-known-to-fail
 *
 * check-error-start
sizeof-function.c:4:16: error: expression using addressof on a builtin function
 * check-error-end
 */
