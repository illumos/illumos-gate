enum a {
	A = ~0ULL,
};

static enum a a = A;

/*
 * check-name: bug-rshift-ub
 * check-description:
 *	This test trigger(ed) a bug on x86 caused by a
 *	full width shift (which is UB), expecting to get
 *	0 but giving the unshifted value and as result
 *	the type is invalid:
 *		warning: incorrect type in initializer (invalid types)
 *			 expected bad type enum a static [toplevel] a
 */
