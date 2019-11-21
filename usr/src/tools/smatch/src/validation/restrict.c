void f00(void *restrict  dst);
void f01(void *restrict *dst);
void f02(void *restrict *dst);
void f03(void *restrict *dst);

void *restrict rp;
void * up;

void f00(void *dst)	  { }	/* check-should-pass */
void f01(typeof(&rp) dst) { }	/* check-should-pass */
void f02(void **dst)	  { }	/* check-should-fail */
void f03(typeof(&up) dst) { }	/* check-should-fail */

void foo(void)
{
	rp = up;		/* check-should-pass */
	up = rp;		/* check-should-pass */
}

void ref(void)
{
	void *const qp;
	void * up;
	extern void *const *pqp;
	extern void **pup;

	pqp = &qp;		/* check-should-pass */
	pqp = &up;		/* check-should-pass */
	pqp = pup;

	pup = &up;		/* check-should-pass */

	pup = &qp;		/* check-should-fail */
	pup = pqp;		/* check-should-fail */
}

void bar(void)
{
	extern void *restrict *prp;
	extern void **pup;

	prp = &rp;		/* check-should-pass */
	prp = &up;		/* check-should-pass */
	prp = pup;

	pup = &up;		/* check-should-pass */

	pup = &rp;		/* check-should-fail */
	pup = prp;		/* check-should-fail */
}

void baz(void)
{
	extern typeof(&rp) prp;
	extern typeof(&up) pup;

	prp = &rp;		/* check-should-pass */
	prp = &up;		/* check-should-pass */
	prp = pup;

	pup = &up;		/* check-should-pass */

	pup = &rp;		/* check-should-fail */
	pup = prp;		/* check-should-fail */
}

/*
 * check-name: restrict qualifier
 * check-command: sparse -Wno-decl $file;
 *
 * check-error-start
restrict.c:11:6: error: symbol 'f02' redeclared with different type (originally declared at restrict.c:3) - incompatible argument 1 (different modifiers)
restrict.c:12:6: error: symbol 'f03' redeclared with different type (originally declared at restrict.c:4) - incompatible argument 1 (different modifiers)
restrict.c:33:13: warning: incorrect type in assignment (different modifiers)
restrict.c:33:13:    expected void **extern [assigned] pup
restrict.c:33:13:    got void *const *
restrict.c:34:13: warning: incorrect type in assignment (different modifiers)
restrict.c:34:13:    expected void **extern [assigned] pup
restrict.c:34:13:    got void *const *extern [assigned] pqp
restrict.c:48:13: warning: incorrect type in assignment (different modifiers)
restrict.c:48:13:    expected void **extern [assigned] pup
restrict.c:48:13:    got void *restrict *
restrict.c:49:13: warning: incorrect type in assignment (different modifiers)
restrict.c:49:13:    expected void **extern [assigned] pup
restrict.c:49:13:    got void *restrict *extern [assigned] prp
restrict.c:63:13: warning: incorrect type in assignment (different modifiers)
restrict.c:63:13:    expected void **extern [assigned] pup
restrict.c:63:13:    got void *restrict *
restrict.c:64:13: warning: incorrect type in assignment (different modifiers)
restrict.c:64:13:    expected void **extern [assigned] pup
restrict.c:64:13:    got void *restrict *extern [assigned] prp
 * check-error-end
 */
