struct a {
	int field;
};
struct b {
	int field;
};

typedef union {
	struct a *a;
	struct b *b;
} transparent_arg __attribute__((__transparent_union__));

static void foo(transparent_arg arg)
{
}

static void bar(void)
{
	struct b arg = { 0 };
	foo((struct a *) &arg);
}

/*
 * check-name: Transparent union attribute.
 */
