#define W	3
#define	S	8
#define M	(W << S)

static inline int fun(unsigned int x, unsigned int y)
{
	return ((x & M) | (y << S)) >> S;
}

short foo(unsigned int x, unsigned int y)
{
	return fun(x, y) & W;
}

/*
 * check-name: and-or-mask3s
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-pattern(1): lsr\\.
 * check-output-pattern(1): or\\.
 * check-output-pattern(1): and\\.
 * check-output-excludes: shl\\.
 */
