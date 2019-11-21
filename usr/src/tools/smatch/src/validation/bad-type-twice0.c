static int foo(a)
{
	return a ? : 1;
}

/*
 * check-name: bad-type-twice0
 *
 * check-error-start
bad-type-twice0.c:3:16: error: incorrect type in conditional (non-scalar type)
bad-type-twice0.c:3:16:    got incomplete type a
 * check-error-end
 */
