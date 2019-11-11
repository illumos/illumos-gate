
static void ok(int a, int b, int c)
{
	__range__(a, 0, 8);
	__range__(a, b, c);
}

static void ko(int a, int b, int c)
{
	__range__ a, 0, 8;
	__range__ a, b, c;
}

/*
 * check-name: range syntax
 *
 * check-error-start
range-syntax.c:10:19: error: Expected ( after __range__ statement
range-syntax.c:10:19: error: got a
range-syntax.c:11:19: error: Expected ( after __range__ statement
range-syntax.c:11:19: error: got a
 * check-error-end
 */
