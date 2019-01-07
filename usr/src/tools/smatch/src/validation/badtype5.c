#define	__force		__attribute__((force))

int foo(int *addr);
int foo(int *addr)
{
	return *(*((typeof(addr) __force *) addr));
}

/*
 * check-name: badtype5.c
 * check-description:
 *	evaluate_dereference() used to miss a call to
 *	examine_symbol_type(). This, in the present, left
 *	a SYM_TYPEOF as type for the last dereferencing
 *	which produced "error: cannot dereference this type".
 *	The presence of the __force and the typeof is needed
 *	to create the situation.
 */
