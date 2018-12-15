/*
 *  Bug in original tree: (real_v ? : x) had been treated as equivalent of
 *  (real_v == 0 ? real_v == 0 : x), which gives the wrong type (and no
 *  warning from the testcase below).
 */
static int x;
static double y;
int a(void)
{
	return ~(y ? : x);	/* should warn */
}
/*
 * check-name: Two-argument conditional expression types
 *
 * check-error-start
cond_expr.c:10:16: error: incompatible types for operation (~)
cond_expr.c:10:16:    argument has type double
 * check-error-end
 */
