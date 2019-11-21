static double foo(double a, int p)
{
	return a * ((p & 0) + 2);
}

/*
 * check-name: fpcast-constant
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-contains: scvtf\\.
 * check-output-excludes: fmul\\..*\\$2
 */
