static int f(int n)
{
	__label__ n;
n:	return n;
}
static int g(int n)
{
n:	return n;
}
/*
 * check-name: __label__ scope
 */
