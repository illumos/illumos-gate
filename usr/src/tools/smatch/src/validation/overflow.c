extern int a;

int a = __INT_MAX__ * 2;

int foo(void)
{
	return __INT_MAX__ * 2;
}

/*
 * check-name: overflow
 * check-command: sparse -Wno-decl $file
 *
 * check-known-to-fail
 * check-error-start
bug-overflow.c:3:21: warning: integer overflow in expression
bug-overflow.c:7:28: warning: integer overflow in expression
 * check-error-end
 */
