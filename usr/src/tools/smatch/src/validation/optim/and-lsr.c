// (x & M) >> S to (x >> S) & (M >> S)

unsigned int foo(unsigned int x)
{
	return (x & 0xffff) >> 12;
}

/*
 * check-name: and-lsr
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: and\\..*\\$15
 * check-output-excludes: and\\..*\\$0xffff
 */
