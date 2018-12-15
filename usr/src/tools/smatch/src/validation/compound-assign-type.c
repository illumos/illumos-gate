static unsigned int foo(unsigned int x, long a)
{
	x /= a;
	return x;
}

/*
 * check-name: compound-assign-type
 * check-command: test-linearize -m64 $file
 * check-output-ignore
 *
 * check-output-excludes: divu\\.32
 * check-output-contains: divs\\.64
 * check-output-contains: scast\\.32
 */
