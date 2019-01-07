static int foo(int a)
{
	a |=\1;

	return a;
}
/*
 * check-name: bad assignment
 *
 * check-error-start
bad-assignment.c:3:13: error: Expected ; at end of statement
bad-assignment.c:3:13: error: got \
 * check-error-end
 */
