#define	__user		__attribute__((address_space(1)))
#define	__noderef	__attribute__((noderef))
#define	__bitwise	__attribute__((bitwise))
#define	__nocast	__attribute__((nocast))
#define	__safe		__attribute__((safe))


/* Should be inherited? */
static void test_const(void)
{
	const int o;
	int *p = &o;			/* check-should-fail */
}

static void test_volatile(void)
{
	volatile int o;
	int *p = &o;			/* check-should-fail */
}

static void test_noderef(void)
{
	int __noderef o;
	int *p = &o;			/* check-should-fail */
}

static void test_bitwise(void)
{
	int __bitwise o;
	int *p = &o;			/* check-should-fail */
}

static void test_user(void)
{
	int __user o;
	int *p = &o;			/* check-should-fail */
}

static void test_nocast(void)
{
	int __nocast o;
	int __nocast *p = &o;		/* check-should-pass */
}

/* Should be ignored? */
static void test_static(void)
{
	/* storage is not inherited */
	static int o;
	int *p = &o;			/* check-should-pass */
}

static void test_tls(void)
{
	/* storage is not inherited */
	static __thread int o;
	int *p = &o;			/* check-should-pass */
}

/*
 * check-name: ptr-inherit.c
 *
 * check-error-start
ptr-inherit.c:12:19: warning: incorrect type in initializer (different modifiers)
ptr-inherit.c:12:19:    expected int *p
ptr-inherit.c:12:19:    got int const *<noident>
ptr-inherit.c:18:19: warning: incorrect type in initializer (different modifiers)
ptr-inherit.c:18:19:    expected int *p
ptr-inherit.c:18:19:    got int volatile *<noident>
ptr-inherit.c:24:19: warning: incorrect type in initializer (different modifiers)
ptr-inherit.c:24:19:    expected int *p
ptr-inherit.c:24:19:    got int [noderef] *<noident>
ptr-inherit.c:30:19: warning: incorrect type in initializer (different base types)
ptr-inherit.c:30:19:    expected int *p
ptr-inherit.c:30:19:    got restricted int *<noident>
ptr-inherit.c:36:19: warning: incorrect type in initializer (different address spaces)
ptr-inherit.c:36:19:    expected int *p
ptr-inherit.c:36:19:    got int <asn:1>*<noident>
 * check-error-end
 */
