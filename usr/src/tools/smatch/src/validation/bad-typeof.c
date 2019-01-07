static int fun(void)
{
	typeof() a;
	int b;

	a = b;
}
/*
 * check-name: Bad typeof syntax segfault
 *
 * check-error-start
bad-typeof.c:3:16: error: expected expression after the '(' token
 * check-error-end
 */
