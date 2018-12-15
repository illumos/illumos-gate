extern void afun(void);
extern void vcond(void);
static int array[3];

struct state {
	int nr:2;
};

enum number {
	zero,
	one,
	two,
	many,
};

static int bad_if(struct state s)
{
	if (vcond()) return 1;
	if (s) return 1;
	return 0;
}
static void bad_if2(int *a, int *b)
{
	if (vcond()) *a = 1;
	*b = 0;
}
static int bad_sel(struct state s)
{
	return vcond() ? 1 : 0;
	return s ? 1 : 0;
}
static int bad_loop_void(void)
{
	while (vcond())
		;
	for (;vcond();)
		;
	do
		;
	while (vcond());
	return 0;
}


static int good_if_int(int a, _Bool b, long c, unsigned char d)
{
	if (a) return 1;
	if (b) return 1;
	if (c) return 1;
	if (d) return 1;
	return 0;
}
static int good_if_float(float a, double b)
{
	if (a) return 1;
	if (b) return 1;
	return 0;
}
static int good_if_enum(void)
{
	if (many) return 1;
	return 0;
}
static int good_if_bitfield(struct state s, struct state *p)
{
	if (s.nr) return 1;
	if (p->nr) return 1;
	return 0;
}
static int good_if_ptr(void *ptr)
{
	if (ptr) return 1;
	if (array) return 1;
	if (afun) return 1;
	return 0;
}

/*
 * check-name: conditional-type
 *
 * check-error-start
conditional-type.c:18:18: error: incorrect type in conditional
conditional-type.c:18:18:    got void
conditional-type.c:19:13: error: incorrect type in conditional
conditional-type.c:19:13:    got struct state s
conditional-type.c:24:18: error: incorrect type in conditional
conditional-type.c:24:18:    got void
conditional-type.c:29:21: error: incorrect type in conditional
conditional-type.c:29:21:    got void
conditional-type.c:30:16: error: incorrect type in conditional
conditional-type.c:30:16:    got struct state s
conditional-type.c:34:21: error: incorrect type in conditional
conditional-type.c:34:21:    got void
conditional-type.c:36:20: error: incorrect type in conditional
conditional-type.c:36:20:    got void
conditional-type.c:40:21: error: incorrect type in conditional
conditional-type.c:40:21:    got void
 * check-error-end
 */
