static int bad_scope(void)
{
	int r = 0;

	for (int i = 0; i < 10; i++) {
		r = i;
	}

	return i;			/* check-should-fail */
}

static int c99(void)
{
	int r = 0;

	for (         int i = 0; i < 10; i++)	/* check-should-pass */
		r = i;
	for (    auto int j = 0; j < 10; j++)	/* check-should-pass */
		r = j;
	for (register int k = 0; k < 10; k++)	/* check-should-pass */
		r = k;
	for (  extern int l = 0; l < 10; l++)	/* check-should-fail */
		r = l;
	for (  extern int m;     m < 10; m++)	/* check-should-fail */
		r = m;
	for (  static int n = 0; n < 10; n++)	/* check-should-fail */
		r = n;
	return r;
}

/*
 * check-name: C99 for-loop declarations
 *
 * check-error-start
c99-for-loop-decl.c:22:27: error: non-local var 'l' in for-loop initializer
c99-for-loop-decl.c:24:27: error: non-local var 'm' in for-loop initializer
c99-for-loop-decl.c:26:27: error: non-local var 'n' in for-loop initializer
c99-for-loop-decl.c:9:16: error: undefined identifier 'i'
 * check-error-end
 */
