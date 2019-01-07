struct st;

static int foo(int a)
{
	return (struct/st *) a;
}
/*
 * check-name: Bad cast syntax
 *
 * check-error-start
bad-cast.c:5:23: error: expected declaration
bad-cast.c:5:23: error: Expected ) at end of cast operator
bad-cast.c:5:23: error: got /
 * check-error-end
 */
