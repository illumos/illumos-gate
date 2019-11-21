extern unsigned long l;

int foo(void) {
	return (int) (typeof(fundecl(0))) l;
}

/*
 * check-name: cast-bad 01
 *
 * check-error-start
cast-bad-01.c:4:30: error: undefined identifier 'fundecl'
 * check-error-end
 */
