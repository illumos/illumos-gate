#define W	3
#define	S	8
#define M	(W << S)

static inline int fun(unsigned int x, unsigned int y)
{
	return ((x & W) | (y >> S)) << S;
}

int foo(unsigned int x, unsigned int y)
{
	return fun(x, y) & M;
}

/*
 * check-name: and-or-mask4
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-pattern(1): shl\\.
 * check-output-pattern(1): or\\.
 * check-output-pattern(1): and\\.
 * check-output-excludes: lsr\\.
 */
