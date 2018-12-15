static int a[] = {
	[0] = 0,		// OK
	[\0] = 1,		// KO
};
/*
 * check-name: Bad array designated initializer
 *
 * check-error-start
bad-array-designated-initializer.c:3:10: error: Expected constant expression
bad-array-designated-initializer.c:3:10: error: Expected } at end of initializer
bad-array-designated-initializer.c:3:10: error: got \
 * check-error-end
 */
