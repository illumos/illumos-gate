// ((x & M) | y) >> S to (y >> S) when (M >> S) == 0

unsigned int foo(unsigned int x, unsigned int y)
{
	return ((x & 0xff) | y) >> 8;
}

/*
 * check-name: mask-lsr
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: %arg1
 */
