static  float foof( float a) { return ( float) a; }
static double food(double a) { return (double) a; }
static long double fool(long double a) { return (long double) a; }

/*
 * check-name: fpcast-nop
 * check-description:
 *	Verify that unneeded casts between same-type
 *	floats are also optimized away.
 *
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-excludes: fpcast\\.
 */
