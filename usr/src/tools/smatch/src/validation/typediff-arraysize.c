extern int ok0[];	int ok0[1];	// OK
extern int ok1[1];	int ok1[];	// OK but size should be 1
extern int ko1[1];	int ko1[2];	// KO

/*
 * check-name: typediff-arraysize
 * check-known-to-fail
 *
 * check-error-start
typediff-arraysize.c:3:29: error: symbol 'ko1' redeclared with different type (originally declared at typediff-arraysize.c:3) - different array sizes
 * check-error-end
 */
