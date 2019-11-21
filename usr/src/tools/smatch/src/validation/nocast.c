#define	__nocast	__attribute__((nocast))
typedef unsigned long __nocast ulong_nc_t;

extern void use_val(ulong_nc_t);
extern void use_ptr(ulong_nc_t *);

/* use address */
static void good_use_address(void)
{
	ulong_nc_t t;

	use_ptr(&t);
}

static ulong_nc_t *good_ret_address(void)
{
	static ulong_nc_t t;

	return &t;
}

static ulong_nc_t good_deref(ulong_nc_t *t)
{
	return *t;
}

/* assign value */
static ulong_nc_t t;
static ulong_nc_t good_assign_self = t;
static unsigned long good_assign_sametype = t;

/* assign pointer */
static ulong_nc_t *good_ptr = &t;
static ulong_nc_t *bad_ptr_to = 1UL;
static unsigned long *bad_ptr_from = &t;

/* arithmetic operation */
static ulong_nc_t good_arith(ulong_nc_t t, unsigned int n)
{
	return t + n;
}

/* implicit cast to other types */
static unsigned long good_ret_samecast(ulong_nc_t t)
{
	return t;
}
static unsigned long long bad_ret_biggercast(ulong_nc_t t)
{
	return t;
}
static long bad_ret_signcast(ulong_nc_t t)
{
	return t;
}
static short bad_ret_smallercast(ulong_nc_t t)
{
	return t;
}

static void assign_val(ulong_nc_t t)
{
	ulong_nc_t good_c = t;
	unsigned long good_ul = t;
	unsigned long long bad_ull = t;
	long bad_l = t;
	short bad_i = t;
}

static void assign_via_ptr(ulong_nc_t *t)
{
	ulong_nc_t good_c = *t;
	unsigned long good_ul = *t;
	unsigned long long bad_ull = *t;
	long bad_l = *t;
	short bad_i = *t;
}

static void assign_ptr(ulong_nc_t *t)
{
	ulong_nc_t *good_same_type = t;
	unsigned long *bad_mod = t;
	unsigned long long __nocast *bad_size = t;
	short __nocast *bad_i = t;
	long __nocast *bad_l = t;
}

/* implicit cast to nocast */
static void implicit_assign_to(void)
{
	ulong_nc_t t;
	unsigned long ul = 1;
	unsigned short us = 1;
	unsigned long long ull = 1;
	long l = 1;

	t = ul;		/* implicit to nocast from same type: OK? */
	t = us;
	t = ull;
	t = l;
}

static void bad_implicit_arg_to(void)
{
	unsigned long ul = 1;
	unsigned short us = 1;
	unsigned long long ull = 1;
	long l = 1;

	use_val(ul);	/* implicit to nocast from same type: OK? */
	use_val(us);
	use_val(ull);
	use_val(l);
}

/* implicit cast from nocast */
static unsigned long good_implicit_ret_ul(ulong_nc_t t)
{
	return t;	/* implicit to nocast from same type: OK? */
}

static unsigned short bad_implicit_ret_us(ulong_nc_t t)
{
	return t;
}

static unsigned long long bad_implicit_ret_ull(ulong_nc_t t)
{
	return t;
}

static long bad_implicit_ret_l(ulong_nc_t t)
{
	return t;
}

/* FIXME: explicit cast: should we complain? */
static ulong_nc_t good_samecast(ulong_nc_t v)
{
	return (ulong_nc_t) v;
}

static ulong_nc_t bad_tocast(unsigned long v)
{
	return (ulong_nc_t) v;
}

static unsigned long bad_fromcast(ulong_nc_t v)
{
	return (unsigned long) v;
}

/*
 * check-name: nocast.c
 *
 * check-error-start
nocast.c:34:33: warning: incorrect type in initializer (different base types)
nocast.c:34:33:    expected unsigned long [nocast] [usertype] *static [toplevel] bad_ptr_to
nocast.c:34:33:    got unsigned long
nocast.c:34:33: warning: implicit cast to nocast type
nocast.c:35:39: warning: incorrect type in initializer (different modifiers)
nocast.c:35:39:    expected unsigned long *static [toplevel] bad_ptr_from
nocast.c:35:39:    got unsigned long [nocast] *
nocast.c:35:39: warning: implicit cast from nocast type
nocast.c:50:16: warning: implicit cast from nocast type
nocast.c:54:16: warning: implicit cast from nocast type
nocast.c:58:16: warning: implicit cast from nocast type
nocast.c:65:38: warning: implicit cast from nocast type
nocast.c:66:22: warning: implicit cast from nocast type
nocast.c:67:23: warning: implicit cast from nocast type
nocast.c:74:38: warning: implicit cast from nocast type
nocast.c:75:22: warning: implicit cast from nocast type
nocast.c:76:23: warning: implicit cast from nocast type
nocast.c:82:34: warning: incorrect type in initializer (different modifiers)
nocast.c:82:34:    expected unsigned long *bad_mod
nocast.c:82:34:    got unsigned long [nocast] [usertype] *t
nocast.c:82:34: warning: implicit cast from nocast type
nocast.c:83:49: warning: incorrect type in initializer (different type sizes)
nocast.c:83:49:    expected unsigned long long [nocast] *bad_size
nocast.c:83:49:    got unsigned long [nocast] [usertype] *t
nocast.c:83:49: warning: implicit cast to/from nocast type
nocast.c:84:33: warning: incorrect type in initializer (different type sizes)
nocast.c:84:33:    expected short [nocast] *bad_i
nocast.c:84:33:    got unsigned long [nocast] [usertype] *t
nocast.c:84:33: warning: implicit cast to/from nocast type
nocast.c:85:32: warning: implicit cast to/from nocast type
nocast.c:98:13: warning: implicit cast to nocast type
nocast.c:99:13: warning: implicit cast to nocast type
nocast.c:100:13: warning: implicit cast to nocast type
nocast.c:111:17: warning: implicit cast to nocast type
nocast.c:112:17: warning: implicit cast to nocast type
nocast.c:113:17: warning: implicit cast to nocast type
nocast.c:124:16: warning: implicit cast from nocast type
nocast.c:129:16: warning: implicit cast from nocast type
nocast.c:134:16: warning: implicit cast from nocast type
 * check-error-end
 */
