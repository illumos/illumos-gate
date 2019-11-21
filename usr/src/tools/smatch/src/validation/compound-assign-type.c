static unsigned int foo(unsigned int x, long a)
{
	x /= a;
	return x;
}

/*
 * check-name: compound-assign-type
 * check-command: test-linearize -m64 $file
 * check-assert: sizeof(long) == 8
 *
 * check-output-ignore
 *
 * check-output-excludes: divu\\.32
 * check-output-contains: divs\\.64
 * check-output-contains: zext.64 .* (32) %arg1
 * check-output-contains: trunc.32 .* (64)
 */
