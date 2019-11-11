#define uint unsigned int

uint xtc_umul_ytc(uint x, uint y) { return (x * 3) * (y * 2); }

/*
 * check-name: canonical-muldiv
 * check-description:
 *	1) verify that constants in mul chains are
 *	   pushed at the right of the whole chain.
 *	   For example '(a * 3) * b' must be canonicalized into '(a * b) * 1'
 *	   This is needed in general for constant simplification;
 *	   for example, for:
 *		'(a * 3) * (b * 2)'
 *	   to be simplified into:
 *		'(a * b) * 6'
 *
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 * check-output-ignore
 *
 * check-output-excludes: \\$3
 * check-output-excludes: \\$2
 * check-output-contains: \\$6
 */
