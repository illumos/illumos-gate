struct A {
	int a[1];
	int b;
};

extern int c;

static int o[] = {
	[__builtin_offsetof(struct A, b)] = 0,		// OK
	[__builtin_offsetof(struct A, a[0])] = 0,	// OK
	[__builtin_offsetof(struct A, a[0*0])] = 0,	// OK
	[__builtin_offsetof(struct A, a[c])] = 0	// KO
};

/*
 * check-name: __builtin_offsetof() constness verification.
 *
 * check-error-start
constexpr-offsetof.c:12:39: error: bad constant expression
 * check-error-end
 */
