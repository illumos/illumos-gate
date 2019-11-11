static int foo(void)
{
	switch () {
	case 0:
		return 0;
	default:
		return 1;
	}
}

static int bar(void)
{
	if ()
		return 0;
	else
		return 1;
}

/*
 * check-name: empty expression
 *
 * check-error-start
empty-expr.c:3:17: error: an expression is expected before ')'
empty-expr.c:13:13: error: an expression is expected before ')'
 * check-error-end
 */
