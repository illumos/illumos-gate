extern type_t fun(int);

int foo(int x, int y)
{
	return ((int)fun(y)) + x;
}

/*
 * check-name: bad-type-twice2
 *
 * check-error-start
bad-type-twice2.c:1:8: warning: 'type_t' has implicit type
bad-type-twice2.c:1:15: error: Expected ; at end of declaration
bad-type-twice2.c:1:15: error: got fun
bad-type-twice2.c:5:22: error: undefined identifier 'fun'
bad-type-twice2.c:5:18: error: cast from unknown type
 * check-error-end
 */
